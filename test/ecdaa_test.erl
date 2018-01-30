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

member_sign_no_basename_test() ->
  Signature = ecdaa:sign("../priv/message.bin", "../priv/sk.bin", "../priv/cred.bin"),
  io:format("Got signature ~p", [Signature]),
  ?assert(is_binary(Signature)),
  ?assert(size(Signature) == ?SIG_LENGTH),

  %% either filename or binary supported for message field, test it too
  Signature = ecdaa:sign(<<"Hello ECDAA!">>, "../priv/sk.bin", "priv/cred.bin").


member_sign_with_basename_test() ->
  Signature = ecdaa:sign("../priv/message.bin", "../priv/sk.bin", "../priv/cred.bin", "../priv/basename.bin"),
  io:format("Got signature ~p", [Signature]),
  ?assert(is_binary(Signature)),
  ?assert(size(Signature) == ?SIG_LENGTH),

  %% either filename and/or binary supported for message and/or mybasename field, test it too
  Signature = ecdaa:sign(<<"Hello ECDAA!">>, "../priv/sk.bin", "../priv/cred.bin", <<"mybasename">>).