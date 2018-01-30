#include <ecdaa.h>
#include <erl_nif.h>

#define MAX_MESSAGE_SIZE 1024
#define MAX_BASENAME_SIZE 1024

static ERL_NIF_TERM
do_sign(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{

     ErlNifBinary message;
     ErlNifBinary secret_key;
     ErlNifBinary credential;
     ErlNifBinary basename;

//     uint8_t *basename = NULL;

     if(argc < 3) {
        return enif_make_badarg(env);
     }

     if(!enif_inspect_binary(env, argv[0], &message)) {
        return enif_make_badarg(env);
     }
     else if (message.size <= 0 || message.size > MAX_MESSAGE_SIZE) {
        fprintf(stderr, "Invalid message size %lu of message \"%s\"\n", (unsigned long) message.size, message.data);
        return enif_make_badarg(env);
     }

     if(!enif_inspect_binary(env, argv[1], &secret_key)) {
        return enif_make_badarg(env);
     }
     else if ( ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH != secret_key.size) {
        fprintf(stderr, "Got bad size secret key: expected %lu got %lu (size of \"%s\")\n", (unsigned long) ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH, (unsigned long) secret_key.size, secret_key.data);
        return enif_make_badarg(env);
     }

     if(!enif_inspect_binary(env, argv[2], &credential)) {
        return enif_make_badarg(env);
     }
     else if ( ECDAA_CREDENTIAL_FP256BN_LENGTH != credential.size) {
        fprintf(stderr, "Got bad size credential: expected %lu got %lu (size of \"%s\")\n", (unsigned long) ECDAA_CREDENTIAL_FP256BN_LENGTH, (unsigned long) credential.size, credential.data);
        return enif_make_badarg(env);
     }

     if(argc == 4){
        if(!enif_inspect_binary(env, argv[3], &basename)) {
            return enif_make_badarg(env);
        }
        else if (basename.size <= 0 || basename.size > MAX_BASENAME_SIZE) {
            fprintf(stderr, "Invalid basename size %lu of basename \"%s\"\n", (unsigned long) basename.size, basename.data);
            return enif_make_badarg(env);
        }
     }



//

      // Initialize PRNG
      struct ecdaa_prng rng;
      if (0 != ecdaa_prng_init(&rng)) {
          fputs("Error initializing ecdaa_prng\n", stderr);
           return enif_make_int(env, 1);
      }

      // Validate member secret key
      struct ecdaa_member_secret_key_FP256BN sk;

      if ( 0 != ecdaa_member_secret_key_FP256BN_deserialize(&sk, secret_key.data)) {
          fputs("Error deserializing member secret key\n", stderr);
          return enif_make_int(env, 1);
      }

    // Validate credential arg
      struct ecdaa_credential_FP256BN cred;

      if (0 != ecdaa_credential_FP256BN_deserialize(&cred, credential.data)) {
          fputs("Error deserializing member credential\n", stderr);
          return enif_make_int(env, 1);
      }

      uint32_t basename_len = 0;
      uint8_t *basename_data = NULL;
      if (NULL != (void *) basename){
            basename_len = basename.size;
            basename_data = basename.data;
      }

      // Create signature
      struct ecdaa_signature_FP256BN sig;
      if (0 != ecdaa_signature_FP256BN_sign(&sig, message.data, message.size, basename_data, basename_len, &sk, &cred, &rng)) {
          fprintf(stderr, "Error signing message: \"%s\"\n", message.data);
          return enif_make_int(env, 1);
      }

    uint8_t buffer[1024];
    // Write signature to binary
    ecdaa_signature_FP256BN_serialize(buffer, &sig, basename_len != 0);
    if (ECDAA_SIGNATURE_FP256BN_LENGTH != sizeof(buffer)) {
        fprintf(stderr, "Error deserializing signature to a binary buffer: \"%s\"\n", buffer);
        return enif_make_int(env, 1);
    }

    ErlNifBinary *sig_out;
    enif_alloc_binary(ECDAA_SIGNATURE_FP256BN_LENGTH, sig_out);
    memcpy(sig_out->data, buffer, ECDAA_SIGNATURE_FP256BN_LENGTH);

    printf("Signature successfully created!\n");
    return enif_make_binary(env, sig_out);
}

static ErlNifFunc nif_funcs[] = {
    {"do_sign", 3, do_sign},
    {"do_sign", 4, do_sign}
};

ERL_NIF_INIT(ecdaa, nif_funcs, NULL, NULL, NULL, NULL)