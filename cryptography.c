#include "module.h"

DEFINE_MUTEX(password_lock);

/* tie all data structures together */
struct skcipher_def
{
    struct scatterlist sg;
    struct crypto_skcipher *tfm;
    struct skcipher_request *req;
    struct crypto_wait wait;
};

int encrypt_password(char *plaintext, int textsize)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;
    tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, sizeof(key));
    if (err)
    {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req)
    {
        err = -ENOMEM;
        goto out;
    }

    mutex_lock(&password_lock);
    /* Prepare the input data */
    kfree(password_data);
    password_data = kzalloc(PASSWORD_DATA_SIZE, GFP_KERNEL);
    if (!password_data)
    {
        err = -ENOMEM;
        goto out;
    }

    int copy_size = (textsize < PASSWORD_DATA_SIZE) ? textsize : (PASSWORD_DATA_SIZE - 1);
    strncpy(password_data, plaintext, copy_size);

    u8 iv_copy[16];
    strncpy(iv_copy, iv, 16);

    sg_init_one(&sg, password_data, PASSWORD_DATA_SIZE);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, PASSWORD_DATA_SIZE, iv_copy);

    err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    if (err)
    {
        pr_err("Error encrypting data: %d\n", err);
        goto out;
    }

out:
    mutex_unlock(&password_lock);
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    return err;
}

int check_password(char *password)
{
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    int err;
    tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(tfm))
    {
        pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    err = crypto_skcipher_setkey(tfm, key, sizeof(key));
    if (err)
    {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req)
    {
        err = -ENOMEM;
        goto out;
    }

    u8 iv_copy[16];
    strncpy(iv_copy, iv, 16);

    mutex_lock(&password_lock);

    u8 *password_data_copy = kzalloc(PASSWORD_DATA_SIZE, GFP_KERNEL);
    if (!password_data_copy)
    {
        err = -ENOMEM;
        goto out;
    }
    memcpy(password_data_copy, password_data, PASSWORD_DATA_SIZE);

    sg_init_one(&sg, password_data_copy, PASSWORD_DATA_SIZE);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP,
                                  crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, PASSWORD_DATA_SIZE, iv_copy);

    err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    if (err)
    {
        pr_err("Error encrypting data: %d\n", err);
        goto out;
    }

    if (strncmp(password, password_data_copy, strlen(password)) == 0)
    {
        err = 1;
    }
    else
    {
        err = -1;
    }

out:
    mutex_unlock(&password_lock);
    kfree(password_data_copy);
    crypto_free_skcipher(tfm);
    skcipher_request_free(req);
    return err;
}