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
-define(SIG_LENGTH, (2*?MODBYTES_256_56 + 5*(2*?MODBYTES_256_56 + 1))).
-define(MESSAGE_BIN, "message.bin").
-define(CREDENTIAL_BIN, "cred.bin").
-define(SECRET_KEY_BIN, "sk.bin").
-define(BASENAME_BIN, "basename.bin").
-define(BASENAME, <<"mybasename">>).
-define(MESSAGE, <<"Hello ECDAA!">>).


member_sign_no_basename_test() ->
  Priv = ecdaa:priv_dir(),
  Signature = ecdaa:sign(priv_file(Priv, ?MESSAGE_BIN), priv_file(Priv, ?SECRET_KEY_BIN), priv_file(Priv, ?CREDENTIAL_BIN)),
  io:format("Got signature ~p", [Signature]),
  ?assert(is_binary(Signature)),
  ?assert(size(Signature) == ?SIG_LENGTH),

  %% either filename or binary supported for message field, test it too
  Signature = ecdaa:sign(?MESSAGE, priv_file(Priv, ?SECRET_KEY_BIN), priv_file(Priv, ?CREDENTIAL_BIN)).


member_sign_with_basename_test() ->
  Priv = ecdaa:priv_dir(),
  Signature = ecdaa:sign(priv_file(Priv, ?MESSAGE_BIN), priv_file(Priv, ?SECRET_KEY_BIN), priv_file(Priv, ?CREDENTIAL_BIN), priv_file(Priv, ?BASENAME_BIN)),
  io:format("Got signature ~p", [Signature]),
  ?assert(is_binary(Signature)),
  ?assert(size(Signature) == ?SIG_LENGTH),

  %% either filename and/or binary supported for message and/or mybasename field, test it too
  Signature = ecdaa:sign(?MESSAGE, priv_file(Priv, ?SECRET_KEY_BIN), priv_file(Priv, ?CREDENTIAL_BIN), ?BASENAME).

priv_file(PrivDir, Filename)->
  filename:join([PrivDir, Filename]).