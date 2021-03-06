%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 29. Jan 2018 12:23 PM
%%%-------------------------------------------------------------------
-module(ecdaa_test).
-author("iguberman").

-include_lib("eunit/include/eunit.hrl").

-define(MODBYTES_256_56, 32).
-define(SIG_SIZE, (2*?MODBYTES_256_56 + 4*(2*?MODBYTES_256_56 + 1))).
-define(SIG_SIZE_WITH_BN, (2*?MODBYTES_256_56 + 5*(2*?MODBYTES_256_56 + 1))).
-define(MESSAGE_BIN, "message.bin").
-define(CREDENTIAL_BIN, "cred.bin").
-define(SECRET_KEY_BIN, "sk.bin").
-define(SIG_BIN, "sig.bin").
-define(GPK_BIN, "gpk.bin").
-define(SIG_NO_BASENAME_BIN, "sig_no_basename.bin").
-define(BASENAME_BIN, "basename.bin").
-define(BASENAME, <<"mybasename">>).
-define(MESSAGE, <<"Hello ECDAA!">>).
-define(REV_LIST_BIN, "sk_revocation_list.bin").
-define(BN_REV_LIST_BIN, "bn_revocation_list.bin").
-define(SIG_VERIFIED, "Signature successfully verified!").
-define(TEST_DATA_DIR, "test_data").

member_sign_no_basename_test() ->
  Priv = ecdaa:priv_dir(),
  MessageFile = filename:join([Priv, ?TEST_DATA_DIR, ?MESSAGE_BIN]),
  SecretKeyFile = filename:join([Priv, ?TEST_DATA_DIR,  ?SECRET_KEY_BIN]),
  GPKFile = filename:join([Priv, ?TEST_DATA_DIR,  ?GPK_BIN]),
  CredFile = filename:join([Priv, ?TEST_DATA_DIR,  ?CREDENTIAL_BIN]),
  RevListFile = filename:join([Priv, ?TEST_DATA_DIR,  ?REV_LIST_BIN]),
  BnRevListFile = filename:join([Priv, ?TEST_DATA_DIR,  ?BN_REV_LIST_BIN]),

  VerifyCmd = "verify " ++ MessageFile ++ " " ++ ?SIG_BIN ++ " " ++ GPKFile ++  " " ++ RevListFile ++ " 0 " ++ BnRevListFile ++ " 0",

  Signature1 = ecdaa:sign(MessageFile, SecretKeyFile, CredFile),
  ?assert(is_binary(Signature1)),
  ?assert(size(Signature1) =:= ?SIG_SIZE),
  io:format("member_sign_no_basename_test() part 1: got signature ~p of size ~b, expecting size ~b~n", [Signature1, size(Signature1), ?SIG_SIZE]),
  file:write_file(?SIG_BIN, Signature1),
  verify_signature(VerifyCmd),

  %% either filename or binary supported for message field, test it too
  Signature2 = ecdaa:sign(?MESSAGE, SecretKeyFile, CredFile),
  file:write_file(?SIG_BIN, Signature2),
  io:format("member_sign_no_basename_test() part 2: got signature ~p of size ~b, expecting size ~b~n", [Signature2, size(Signature2), ?SIG_SIZE]),
  verify_signature(VerifyCmd).


member_sign_with_basename_test() ->
  Priv = ecdaa:priv_dir(),
  MessageFile = filename:join([Priv, ?TEST_DATA_DIR, ?MESSAGE_BIN]),
  BasenameFile = filename:join([Priv, ?TEST_DATA_DIR, ?BASENAME_BIN]),
  SecretKeyFile = filename:join([Priv, ?TEST_DATA_DIR,  ?SECRET_KEY_BIN]),
  GPKFile = filename:join([Priv, ?TEST_DATA_DIR,  ?GPK_BIN]),
  CredFile = filename:join([Priv, ?TEST_DATA_DIR,  ?CREDENTIAL_BIN]),
  RevListFile = filename:join([Priv, ?TEST_DATA_DIR,  ?REV_LIST_BIN]),
  BnRevListFile = filename:join([Priv, ?TEST_DATA_DIR,  ?BN_REV_LIST_BIN]),

  VerifyCmd = "verify " ++ MessageFile ++ " " ++ ?SIG_BIN ++ " " ++ GPKFile ++  " " ++ RevListFile ++ " 0 " ++ BnRevListFile ++ " 0 " ++ BasenameFile,

  Signature1 = ecdaa:sign(MessageFile, SecretKeyFile, CredFile, BasenameFile),
  file:write_file(?SIG_BIN, Signature1),
  ?assert(is_binary(Signature1)),
  ?assert(size(Signature1) =:= ?SIG_SIZE_WITH_BN),
  io:format("member_sign_with_basename_test() part 1: got signature ~p of size ~b, expecting size ~b~n", [Signature1, size(Signature1), ?SIG_SIZE_WITH_BN]),
  verify_signature(VerifyCmd),

  %% either filename and/or binary supported for message and/or mybasename field, test it too
  Signature2 = ecdaa:sign(?MESSAGE, SecretKeyFile, CredFile, ?BASENAME),
  io:format("member_sign_with_basename_test() part 2: got signature ~p of size ~b, expecting size ~b~n", [Signature2, size(Signature2), ?SIG_SIZE_WITH_BN]),
  file:write_file(?SIG_BIN, Signature2),
  ?assert(size(Signature2) =:= ?SIG_SIZE_WITH_BN),
  verify_signature(VerifyCmd).

verify_signature(VerifyCmd)->
  Res = os:cmd(VerifyCmd),
  io:format("Verify result: ~p~n", [Res]),
  ?assert(string:str(Res, ?SIG_VERIFIED) > 0).