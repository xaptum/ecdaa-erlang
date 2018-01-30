#include <ecdaa.h>
#include <erl_nif.h>

ErlNifBinary* BINARY_RESOURCE_TYPE;
ErlNifResourceType* ERLNIF_RESOURCE_TYPE;


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

     if(!enif_inspect_binary(env, argv[1], &secret_key)) {
        return enif_make_badarg(env);
     }

     if(!enif_inspect_binary(env, argv[2], &credential)) {
        return enif_make_badarg(env);
     }

     if(argc == 4){
        if(!enif_inspect_binary(env, argv[3], &basename)) {
            return enif_make_badarg(env);
        }
     }

//    uint8_t buffer[1024];

      // Initialize PRNG
      struct ecdaa_prng rng;
      if (0 != ecdaa_prng_init(&rng)) {
          fputs("Error initializing ecdaa_prng\n", stderr);
           return enif_make_int(env, 1);
      }

      // Read member secret key from disk
//      struct ecdaa_member_secret_key_FP256BN sk;
//      if (ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH != read_file_into_buffer(buffer, ECDAA_MEMBER_SECRET_KEY_FP256BN_LENGTH, args.secret_key_file)) {
//          fprintf(stderr, "Error reading member secret key file: \"%s\"\n", args.secret_key_file);
//          return 1;
//      }

//      if (0 != ecdaa_member_secret_key_FP256BN_deserialize(&sk, buffer)) {
//          fputs("Error deserializing member secret key\n", stderr);
//          return 1;
//      }
//
//      // Read member credential from disk
//      struct ecdaa_credential_FP256BN cred;
//      if (ECDAA_CREDENTIAL_FP256BN_LENGTH != read_file_into_buffer(buffer, ECDAA_CREDENTIAL_FP256BN_LENGTH, args.credential_file)) {
//          fprintf(stderr, "Error reading member credential file: \"%s\"\n", args.credential_file);
//          return 1;
//      }
//
//      if (0 != ecdaa_credential_FP256BN_deserialize(&cred, buffer)) {
//          fputs("Error deserializing member credential\n", stderr);
//          return 1;
//      }
//
//      // Read message file
//      uint8_t message[MAX_MESSAGE_SIZE];
//      int read_ret = read_file_into_buffer(message, sizeof(message), args.message_file);
//      if (read_ret < 0) {
//          fprintf(stderr, "Error reading message file: \"%s\"\n", args.message_file);
//          return 1;
//      }
//      uint32_t msg_len = (uint32_t)read_ret;
//
//      // Read basename file (if requested)
//      uint8_t *basename = NULL;
//      uint32_t basename_len = 0;
//      uint8_t basename_buffer[MAX_MESSAGE_SIZE];
//      if (NULL != args.basename_file) {
//          basename = basename_buffer;
//
//          int read_ret = read_file_into_buffer(basename_buffer, sizeof(basename_buffer), args.basename_file);
//          if (read_ret < 0) {
//              fprintf(stderr, "Error reading basename file: \"%s\"\n", args.basename_file);
//              return 1;
//          }
//          basename_len = (uint32_t)read_ret;
//      }
//
//      // Create signature
//      struct ecdaa_signature_FP256BN sig;
//      if (0 != ecdaa_signature_FP256BN_sign(&sig, message, msg_len, basename, basename_len, &sk, &cred, &rng)) {
//          message[msg_len] = 0;
//          fprintf(stderr, "Error signing message: \"%s\"\n", (char*)message);
//          return 1;
//      }
//
//      // Write signature to file
//      ecdaa_signature_FP256BN_serialize(buffer, &sig, basename_len != 0);
//      if (ECDAA_SIGNATURE_FP256BN_LENGTH != write_buffer_to_file(args.sig_out_file, buffer, ECDAA_SIGNATURE_FP256BN_LENGTH)) {
//          fprintf(stderr, "Error writing signature to file: \"%s\"\n", args.sig_out_file);
//          return 1;
//      }
//
//      printf("Signature successfully created!\n");
//      }

    return enif_make_int(env, 123);
}

static ErlNifFunc nif_funcs[] = {
    {"do_sign", 3, do_sign},
    {"do_sign", 4, do_sign}
};

ERL_NIF_INIT(ecdaa, nif_funcs, NULL, NULL, NULL, NULL)