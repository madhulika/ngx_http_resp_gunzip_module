
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>



static u_char gzheader[10] = { 0x1f, 0x8b, Z_DEFLATED, 0, 0, 0, 0, 0, 0, 3 };
typedef enum gunzip_state_e gunzip_state_e;

enum gunzip_state_e
{
    GUNZIP_STATE_HEADER  = 0,
    GUNZIP_STATE_DATA    = 1,
    GUNZIP_STATE_TRAILER = 2,
};

typedef struct
{
    ngx_flag_t           enable;
    size_t               wbits;
    ngx_bufs_t           bufs;
}ngx_http_resp_gunzip_conf_t;

typedef struct {
    gunzip_state_e      state;
    ngx_chain_t        *in;
    ngx_chain_t        *free;
    ngx_chain_t        *busy;
    ngx_chain_t        *out;
    ngx_chain_t       **last_out;

    ngx_chain_t        *copied;
    ngx_chain_t        *copy_buf;

    ngx_buf_t          *in_buf;
    ngx_buf_t          *out_buf;          /* zstream.next_out */
    ngx_int_t           bufs;

    void               *preallocated;
    char               *free_mem;
    size_t              allocated;

    int                 wbits;

    unsigned            flush:4;
    unsigned            redo:1;        /* deflate may still have some pending output */
    unsigned            done:1;
    unsigned            nomem:1;

    size_t              zin;
    size_t              zout;
    
    size_t              nheader_left;
    size_t              ntrailer_left;
    
    z_stream            zstream;
    ngx_http_request_t *request;
}ngx_http_gunzip_filter_ctx_t;



#if (ngx_HAVE_LITTLE_ENDIAN && ngx_HAVE_NONALIGNED)
struct gztrailer {
    uint32_t  crc32;
    uint32_t  zlen;
};
#else /* ngx_HAVE_BIG_ENDIAN || !ngx_HAVE_NONALIGNED */
struct gztrailer {
    u_char  crc32[4];
    u_char  zlen[4];
};
#endif



static ngx_int_t ngx_http_do_gunzip_filter(
                              ngx_http_gunzip_filter_ctx_t *ctx,
                              ngx_chain_t *in);

static ngx_int_t ngx_http_gunzip_filter_inflate_start(ngx_http_request_t *r,
                              ngx_http_gunzip_filter_ctx_t *ctx);

static ngx_int_t ngx_http_gunzip_filter_add_data(ngx_http_request_t *r,
                              ngx_http_gunzip_filter_ctx_t *ctx);

static ngx_int_t ngx_http_gunzip_filter_get_or_create_iobuf(ngx_http_request_t *r,
                              ngx_http_gunzip_filter_ctx_t *ctx);

static ngx_int_t ngx_http_gunzip_filter_inflate(ngx_http_request_t *r,
                             ngx_http_gunzip_filter_ctx_t *ctx);

static ngx_int_t ngx_http_gunzip_filter_inflate_end(ngx_http_request_t *r,
                             ngx_http_gunzip_filter_ctx_t *ctx);

static void ngx_http_gunzip_filter_memory(ngx_http_request_t *r,
                             ngx_http_gunzip_filter_ctx_t *ctx);

static void *ngx_http_gunzip_filter_alloc(void *opaque, u_int items,
                                          u_int size);

static void ngx_http_gunzip_filter_free(void *opaque, void *address);
static ngx_int_t ngx_http_gunzip_filter_init(ngx_conf_t *cf);
static void *ngx_http_resp_gunzip_create_conf(ngx_conf_t *cf);
static char *ngx_http_resp_gunzip_merge_conf(ngx_conf_t *cf, void *parent, void
 *child);
static char *ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data);
static void ngx_http_gunzip_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_gunzip_filter_ctx_t *ctx);


static ngx_conf_post_handler_pt  ngx_http_gzip_window_p = ngx_http_gzip_window;


static ngx_command_t  ngx_http_gunzip_filter_commands[] = {

    { ngx_string("gunzip"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_resp_gunzip_conf_t, enable),
      NULL},

    { ngx_string("gzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_resp_gunzip_conf_t, bufs),
      NULL },

    { ngx_string("gzip_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_resp_gunzip_conf_t, wbits),
      &ngx_http_gzip_window_p },

    ngx_null_command
};

static ngx_http_module_t  ngx_http_gunzip_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_gunzip_filter_init,            /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_resp_gunzip_create_conf,     /* create location configuration */
    ngx_http_resp_gunzip_merge_conf       /* merge location configuration */
};

ngx_module_t  ngx_http_resp_gunzip_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_gunzip_filter_module_ctx,      /* module context */
    ngx_http_gunzip_filter_commands,         /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;


static void *ngx_http_resp_gunzip_create_conf(ngx_conf_t *cf)
{
    ngx_http_resp_gunzip_conf_t  *conf;
    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_resp_gunzip_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->wbits = NGX_CONF_UNSET_SIZE;
    return conf;
}

static char *ngx_http_resp_gunzip_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_resp_gunzip_conf_t *prev = parent;
    ngx_http_resp_gunzip_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs,
                              (128 * 1024) / ngx_pagesize, ngx_pagesize);


    return NGX_CONF_OK;
}

static int
free_preallocated(ngx_http_gunzip_filter_ctx_t *ctx)
{
    int rc = Z_OK;
    if (ctx->preallocated) { /* why this check */
        rc = inflateEnd(&ctx->zstream);
        ngx_pfree(ctx->request->pool, ctx->preallocated);
        ctx->preallocated = NULL;
    }
    return rc;
}



static inline ngx_flag_t downstream_accept_gzip(const ngx_http_request_t *r)
{
    return 0;

/* why check this? is it not the job of the webserver to check the Accept-Encoding Header and then decide to encode the data or not. 
is this to verify is the webserver is doing its job : Madhu */

/* none of these variables are available in the request header data structure. just making this function return TRUE at this point 
    if(!req_hdr_in->accept_encoding_gzip)
        return FALSE;

    if((ngx_http_downstream_is_end_user(r) || ngx_http_downstream_is_cache(r))
       && req_hdr_in->browser_flags.msie6_or_older
       && !r->domain_cfg->http_gzip->gzip_to_msie6)
        return FALSE; */

}



static ngx_int_t
ngx_http_resp_header_gunzip_filter(ngx_http_request_t *r)
{

    ngx_http_resp_gunzip_conf_t *conf;
    ngx_http_gunzip_filter_ctx_t *ctx;


    conf = ngx_http_get_module_loc_conf(r, ngx_http_resp_gunzip_filter_module);

    if (!conf->enable
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_FORBIDDEN
            && r->headers_out.status != NGX_HTTP_NOT_FOUND)
        || r->header_only
        || (r->gzip_vary != 1)
        || (!r->headers_out.content_encoding)
        || (r->headers_out.content_encoding->value.len == 0)
     //   || (ngx_http_test_content_type(r, &conf->types) == NULL)
        || (ngx_strncmp(r->headers_out.content_encoding->value.data, "gzip", sizeof("gzip")-1) != 0))
    {

        return ngx_http_next_header_filter(r);
    }


    if(downstream_accept_gzip(r)) 
        return ngx_http_next_header_filter(r);

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_gunzip_filter_ctx_t));
     if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_resp_gunzip_filter_module);

    ctx->wbits = conf->wbits;
    ctx->nheader_left = sizeof(gzheader);
    ctx->ntrailer_left = sizeof(struct gztrailer);
    ctx->request = r;
    ctx->state = GUNZIP_STATE_HEADER;
    ngx_http_gunzip_filter_memory(r, ctx);

   /* we get here if the downstream cannot accept the gzip encoding. so we have to remove all the gzip related fields */
   r->headers_out.content_encoding->value.len = 0;
   r->headers_out.content_encoding->value.data = (u_char *)"";
   r->headers_out.content_encoding->hash = 0;
   r->headers_out.content_encoding = NULL;
  
   
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip  filter is used");

    return ngx_http_next_header_filter(r);
}



static ngx_int_t
ngx_gunzip_enqueue_out_buf(ngx_http_gunzip_filter_ctx_t *ctx)
{
    ngx_chain_t    *cl;
    ngx_http_request_t *r = ctx->request; 
    
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->out_buf;
    cl->next = NULL;
    *ctx->last_out = cl;
    ctx->last_out = &cl->next;

    ctx->out_buf = NULL;
    ctx->zstream.next_out = NULL;
    ctx->zstream.avail_out = 0;
    return NGX_OK;
}



static ngx_int_t 
ngx_http_resp_gunzip_body_filter(
                       ngx_http_request_t *r,
                       ngx_chain_t *in)

{
    ngx_int_t rc;
    ngx_buf_t *eof = NULL;
    ngx_http_gunzip_filter_ctx_t *ctx;
    ngx_buf_t *b;


    ctx = ngx_http_get_module_ctx(r, ngx_http_resp_gunzip_filter_module);

    if (ctx == NULL || ctx->done) 
    {
        return ngx_http_next_body_filter(r, in);
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "http gunzip body filter");



/* the 10 gzheader bytes can all come in one buffer, or several buffers in one filter_data call or across several filter_data calls */
    switch(ctx->state) {
    case GUNZIP_STATE_HEADER: 
        for (; in; in=in->next)
        {
            b = in->buf;
            ssize_t consumed;
            if(b->last_buf) 
            {
                eof = b;
                ctx->done = 1;
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "gunzip: filter has received EOF during GUNZIP_STATE_HEADER");
                return  NGX_ERROR;
            }

            /* skip the gzheader */
            consumed = ctx->nheader_left;
            if (consumed < ngx_buf_size(b))
                consumed = ngx_buf_size(b);
            b->pos += consumed;
            ctx->nheader_left -= consumed;

            /* if the buffer is consumed fully after ignoring the header, free it (do we need to do it:Madhu)  and move to the next buffer.
             * if the next buffer is NULL, just exit */
            if(!ngx_buf_size(b)) {
                in = in->next;
                ngx_free(b);
                if (!in)
                    break;
            }

            if(!ctx->nheader_left) {
                ctx->state = GUNZIP_STATE_DATA;
                break;
            }
        }

        if(ctx->state != GUNZIP_STATE_DATA
           || !in)
            return NGX_OK;

        /* else, fall through to inflate data */
    case GUNZIP_STATE_DATA:
         if (!in)
             return NGX_OK;

        rc = ngx_http_do_gunzip_filter(ctx, in);
        if(rc == NGX_ERROR)
            return rc;
         if(ctx->state != GUNZIP_STATE_TRAILER)
            return NGX_OK;
        /* fall through to parse the trailer in ctx->in*/
    case GUNZIP_STATE_TRAILER:
        for(; in; in = in->next) 
        {
            ssize_t consumed;
            b = in->buf;
            if(b->last_buf) { /* can't the trailer be a part of the last buf */
                eof = b;
                if(ctx->done == 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                                "gunzip: filter got EOF before receiving gzip trailer");
                    return NGX_ERROR;
                }
                continue;
            }

            if(ctx->done) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                            "gunzip: filter got extra data after gzip trailer");
                return NGX_ERROR;
            }

            consumed = ctx->ntrailer_left;
            if (consumed < ngx_buf_size(b))
                consumed = ngx_buf_size(b);
            b->pos += consumed;
            ctx->ntrailer_left -= consumed;
            if(!ngx_buf_size(b)) {
                in = in->next;
                if (in == NULL)
                    return NGX_OK;
            }

            if(!ctx->ntrailer_left) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                                 "gunzip: filter got the gzip trailer");
                ctx->done = 1;
            }
        }

        if(ctx->done) {
            if(eof) {
                ctx->out_buf = eof;
            } else {
                eof = ngx_calloc_buf(r->pool);
                if (eof == NULL)
                {
                    return NGX_ERROR;
                }
                eof->memory = 1;
                eof->last_buf = 1;
                eof->pos = (u_char *) CRLF "0" CRLF CRLF;
                eof->last = eof->pos + 7;
                ctx->out_buf=eof;
            }
            ngx_gunzip_enqueue_out_buf(ctx);
            return ngx_http_next_body_filter(r, ctx->out);
        }
    }
   
    return NGX_ERROR; /*unreachable */

}

static ngx_int_t
ngx_http_do_gunzip_filter( ngx_http_gunzip_filter_ctx_t *ctx,
                          ngx_chain_t *in)
{
    int      rc;
    ngx_http_request_t *r = ctx->request;

    if(ctx->preallocated == NULL)
    {
        if(ngx_http_gunzip_filter_inflate_start(r, ctx) != NGX_OK) 
        {
            rc = NGX_ERROR;
            goto DONE;
        }
    }

   if (in) {
        if (ngx_chain_add_copy(r->pool, &ctx->in, in) != NGX_OK) {
            rc = NGX_ERROR;
            goto DONE;
        }
    }

     if (ctx->nomem) {

        /* flush busy buffers */

        if (ngx_http_next_body_filter(r, NULL) == NGX_ERROR) {
            rc = NGX_ERROR;
            goto DONE;
        }


        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_resp_gunzip_filter_module);
        ctx->nomem = 0;
    }

   for (;;){ 
       /* cycle while we can write to the client */
       for ( ;; ) {
           /* cycle while there is data to feed zlib */
       	   /* get input data for inflate */
           rc = ngx_http_gunzip_filter_add_data(r, ctx);
           if (rc == NGX_DECLINED) {
               break;
           } 

           /* we got some input data for zlib to inflate */
           /* create or get output buf for inflate */
           rc = ngx_http_gunzip_filter_get_or_create_iobuf(r, ctx);
           if (rc == NGX_DECLINED) {
               /* too many iobuf has already been created.
               * it is time to flush to the next filter
               */
               break;
           } else if(rc == NGX_ERROR) {
               /* cannot create iobuf */
               goto DONE;
           }

           rc = ngx_http_gunzip_filter_inflate(r, ctx);
           if (rc == NGX_ERROR) {
               /* there is error during inflate */
               goto DONE;
           }

           if(ctx->state == GUNZIP_STATE_TRAILER)
               break;
           /* rc == NGX_OK */
        } /* for( ;; ) */

        if(ctx->out_buf && ngx_buf_size(ctx->out_buf)!=0)
            /* if we haven't appended out_buf to ctx->out, do it now */
            ngx_gunzip_enqueue_out_buf(ctx);

        if (ctx->out == NULL)
        {
             ngx_http_gunzip_filter_free_copy_buf(r, ctx);
             return ctx->busy ? NGX_AGAIN : NGX_OK;

        }
        rc = ngx_http_next_body_filter(r, ctx->out);
         if (rc == NGX_ERROR) {
            goto DONE;
        }

        ngx_http_gunzip_filter_free_copy_buf(r, ctx);

        ngx_chain_update_chains(&ctx->free, &ctx->busy, &ctx->out,
                                (ngx_buf_tag_t) &ngx_http_resp_gunzip_filter_module);
        ctx->last_out = &ctx->out;


        if(ctx->state == GUNZIP_STATE_TRAILER)
            goto DONE;
        /* we can still ask for more output from zlib */
    }

    /* unreachable */
 DONE:
    if(ctx->out) {
         rc = ngx_http_next_body_filter(r, ctx->out);
    }
    ctx->done = 1;
    free_preallocated(ctx);
    return rc;

}

static void
ngx_http_gunzip_filter_memory(ngx_http_request_t *r, 
                              ngx_http_gunzip_filter_ctx_t *ctx)
{
    /* ML: The memory requirement is spelled out at /usr/include/zconf.h */
    ctx->allocated = 10240 + (1 << ctx->wbits);
}


static ngx_int_t ngx_http_gunzip_filter_inflate_start(ngx_http_request_t *r,
                              ngx_http_gunzip_filter_ctx_t *ctx)
{
    int rc;
    ctx->preallocated
        = ngx_palloc(r->pool, ctx->allocated);

    if (ctx->preallocated == NULL)
        return NGX_ERROR;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,"gunzip: filter pre-allocated %uz bytes memory", ctx->allocated);

    ctx->free_mem = ctx->preallocated;
    ctx->zstream.zalloc = ngx_http_gunzip_filter_alloc;
    ctx->zstream.zfree = ngx_http_gunzip_filter_free;
    ctx->zstream.opaque = ctx;

    rc = inflateInit2(&ctx->zstream, - ctx->wbits);
    if (rc != Z_OK) {
        ngx_pfree(r->pool, ctx->preallocated);
        ctx->preallocated = NULL;
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                    "gunzip: inflateInit2() failed: %d", rc);
        return NGX_ERROR;
    }
     ctx->last_out = &ctx->out;

    return NGX_OK;
}



/* if the last ctx->in_buf has been completely consumed,
 * it will find the next ctx->in_buf (which is then assigned to
 * ctx->zstream.next_in)
 *
 */

static ngx_int_t ngx_http_gunzip_filter_add_data(ngx_http_request_t *r,
                              ngx_http_gunzip_filter_ctx_t *ctx)
{
    if (ctx->zstream.avail_in || ctx->redo) {
        return NGX_OK;
    }

   ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in: %p", ctx->in);

   if (ctx->in == NULL) {
        return NGX_DECLINED;
   }

   if (ctx->copy_buf) {
        /*
         * to avoid CPU cache trashing we do not free() just quit buf,
         * but postpone free()ing after zlib compressing and data output
         */

        ctx->copy_buf->next = ctx->copied;
        ctx->copied = ctx->copy_buf;
        ctx->copy_buf = NULL;
    }
    ctx->in_buf = ctx->in->buf;

    if (ctx->in_buf->tag == (ngx_buf_tag_t) &ngx_http_resp_gunzip_filter_module) {
        ctx->copy_buf = ctx->in;
    }

    ctx->in = ctx->in->next;

    ctx->zstream.next_in = ctx->in_buf->pos;
    ctx->zstream.avail_in = ctx->in_buf->last - ctx->in_buf->pos;

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip in_buf:%p ni:%p ai:%ud",
                   ctx->in_buf,
                   ctx->zstream.next_in, ctx->zstream.avail_in);

    if (ctx->in_buf->last_buf) {
        ctx->flush = Z_FINISH;
    } else if (ctx->in_buf->flush) {
        ctx->flush = Z_SYNC_FLUSH;
    }
   return NGX_OK;
}

static ngx_int_t ngx_http_gunzip_filter_get_or_create_iobuf(ngx_http_request_t *r,
                              ngx_http_gunzip_filter_ctx_t *ctx)
{
    ngx_http_resp_gunzip_conf_t *conf; 

    conf = ngx_http_get_module_loc_conf(r, ngx_http_resp_gunzip_filter_module);



    if (ctx->zstream.avail_out) {
        return NGX_OK;
    }
    if (ctx->free) {
        ctx->out_buf = ctx->free->buf;
        ctx->free = ctx->free->next;
    } else if (ctx->bufs < conf->bufs.num) {
    	ctx->out_buf = ngx_create_temp_buf(r->pool, conf->bufs.size);
    	if (ctx->out_buf == NULL) {
    		return NGX_ERROR;
    	}

    	ctx->out_buf->tag = (ngx_buf_tag_t) &ngx_http_resp_gunzip_filter_module;
    	ctx->out_buf->recycled = 1;
    	ctx->bufs++;
    } else {
        ctx->nomem = 1;
        return NGX_DECLINED;
    }

    ctx->zstream.next_out = ctx->out_buf->pos;
    ctx->zstream.avail_out = conf->bufs.size;

    return NGX_OK;

}

static ngx_int_t ngx_http_gunzip_filter_inflate(ngx_http_request_t *r,
                             ngx_http_gunzip_filter_ctx_t *ctx)
{
    int             rc;
    size_t          last_avail_in;
    size_t          last_avail_out;
    u_char         *out_buf_last;
    ngx_buf_t    *out_buf;
    ngx_http_resp_gunzip_conf_t *conf; 

    ngx_log_debug6(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "inflate in: "
                     "ni:%p ai:%ud no:%p ao:%ud fl:%d redo:%d",
                     ctx->zstream.next_in, ctx->zstream.avail_in,
                     ctx->zstream.next_out,
                     ctx->zstream.avail_out,
                     Z_NO_FLUSH, ctx->redo);

    out_buf = ctx->out_buf;
    out_buf_last = out_buf->last;

    last_avail_in = ctx->zstream.avail_in;
    last_avail_out = ctx->zstream.avail_out;
    rc = inflate(&ctx->zstream, Z_NO_FLUSH); /* why do we use this flush value: Madhu */
  
     if (rc != Z_OK && rc != Z_STREAM_END) {
        ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
                      "inflate() failed: %d, %d", ctx->flush, rc);
        return NGX_ERROR;
    }


    ngx_log_debug5(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                     "inflate out: ni:%p ai:%ud no:%p ao:%ud rc:%d",
                     ctx->zstream.next_in, ctx->zstream.avail_in,
                     ctx->zstream.next_out,
                     ctx->zstream.avail_out,
                     rc);

    if(ctx->zstream.next_in) {
        ctx->in_buf->pos = ctx->zstream.next_in;
        if (ctx->zstream.avail_in == 0) {
            ctx->zstream.next_in = NULL;  /*do we need to free this ctx->in: mrs does it and nginx doesn't */
        }
    }

    /* advance out_buf->last */
    out_buf->last = ctx->zstream.next_out;

    if(ctx->zstream.avail_out == 0) {
        /* out_buf has been completely filled.
         * append it to the out chain
         */
        ngx_gunzip_enqueue_out_buf(ctx);
        ctx->redo = 1;

        return NGX_AGAIN;

    } 

    ctx->redo = 0;
    if (rc == Z_STREAM_END) {
        return ngx_http_gunzip_filter_inflate_end(r, ctx);
    }

    conf = ngx_http_get_module_loc_conf(r, ngx_http_resp_gunzip_filter_module);

/*
    if (conf->no_buffer && ctx->in == NULL) {  why are we doing this 

        ngx_gunzip_enqueue_out_buf(ctx);
        return NGX_OK;
    } */

    return NGX_AGAIN;
}

static ngx_int_t ngx_http_gunzip_filter_inflate_end(ngx_http_request_t *r,
                             ngx_http_gunzip_filter_ctx_t *ctx)
{
    int                rc;
    ctx->zin = ctx->zstream.total_in;
    ctx->zout = ctx->zstream.total_out;

    if(ctx->out_buf && (ngx_buf_size(ctx->out_buf)!= 0))
    {
        ngx_gunzip_enqueue_out_buf(ctx);
    }

    rc = free_preallocated(ctx);
    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "gunzip: inflateEnd() failed: %d", rc);
        return NGX_ERROR;
    }

    ctx->state = GUNZIP_STATE_TRAILER;
    ctx->zstream.next_in = NULL;
    ctx->zstream.avail_in = 0;
    ctx->zstream.next_out = NULL;
    ctx->zstream.avail_out = 0;

     ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "gunzip: filter ended decompression with zin:%uz zout:%uz inflated %z bytes",
                   ctx->zin, ctx->zout,
                   ctx->zout - ctx->zin);

    return NGX_OK;
}

static void *
ngx_http_gunzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_http_gunzip_filter_ctx_t *ctx = opaque;
    void        *p;
    ngx_uint_t   alloc;
    alloc = items * size;
    ngx_http_request_t *r = ctx->request;
    if (alloc % 512 != 0 && alloc < 10240) {
        /*
         * The zlib deflate_state allocation, it takes about 9K,
         * we allocate 10K.  Other allocations are divisible by 512.
         */
        alloc = 10240;
    }
    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;
        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                         "gunzip filter alloc: n:%ud s:%ud a:%ud p:%p",
                         items, size, alloc, p);
    } else {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "gunzip filter failed to use preallocated memory: %ud of %ud",
                      items * size, ctx->allocated);
        p = ngx_palloc(r->pool, items * size);
    }
    return p;
}

static void
ngx_http_gunzip_filter_free(void *opaque, void *address)
{
#if 0
    ngx_http_gzip_ctx_t *ctx = opaque;
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, ctx->request->connection->log, 0,
                   "gzip free: %p", address);
#endif
}

static ngx_int_t
ngx_http_gunzip_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_resp_header_gunzip_filter;

     /* body filters */
    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_resp_gunzip_body_filter;

    return NGX_OK;
}


static void
ngx_http_gunzip_filter_free_copy_buf(ngx_http_request_t *r,
    ngx_http_gunzip_filter_ctx_t *ctx)
{
    ngx_chain_t  *cl;

    for (cl = ctx->copied; cl; cl = cl->next) {
        ngx_pfree(r->pool, cl->buf->start);
    }

    ctx->copied = NULL;
}

static char *
ngx_http_gzip_window(ngx_conf_t *cf, void *post, void *data)
{
    size_t *np = data;

    size_t  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return NGX_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
}

