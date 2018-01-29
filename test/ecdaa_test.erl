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
-define(SIG_LENGTH, (2*MODBYTES_256_56 + 5*(2*MODBYTES_256_56 + 1))).

member_sign_no_basename_test() ->
  Signature = ecdaa:sign(<<"Hello ECDAA NIFs!">>, "sk.bin", "cred.bin"),
  io:format("Got signature ~p", [Signature]),
  ?assert(is_binary(Signature)),
  ?assert(size(Signature) == ?SIG_LENGTH).


member_sign_with_basename_test() ->
  Signature = ecdaa:sign(<<"Hello ECDAA NIFs!">>, "sk.bin", "cred.bin", <<"MyBasename">>),
  io:format("Got signature ~p", [Signature]),
  ?assert(is_binary(Signature)),
  ?assert(size(Signature) == ?SIG_LENGTH).