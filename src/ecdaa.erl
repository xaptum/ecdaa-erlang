%%%-------------------------------------------------------------------
%%% @author iguberman
%%% @copyright (C) 2018, Xaptum, Inc.
%%% @doc
%%%
%%% @end
%%% Created : 19. Jan 2018 4:45 PM
%%%-------------------------------------------------------------------
-module(ecdaa).
-author("iguberman").


%% API
-export([
  ecdaa_sign/3,
  ecdaa_sign/4,
  ecdaa_do_sign/3,
  ecdaa_do_sign/4]).

-type signature() :: <<_:128>>.

init() ->
  ok = erlang:load_nif("./ecdaa", 0).

-spec ecdaa_sign(Message::binary(), SecretKeyFile::list(), CredentialFile::list()) -> signature().
ecdaa_sign(Message, SecretKeyFile, CredentialFile) when is_binary(Message) ->
  {ok, SecretKey} = file:read_file(SecretKeyFile),
  {ok, Credential} = file:read_file(CredentialFile),
  ecdaa_do_sign(Message, SecretKey, Credential).

-spec ecdaa_sign(Message::binary(), SecretKeyFile::list(), CredentialFile::list(), Basename::binary()) -> signature().
ecdaa_sign(Message, SecretKeyFile, CredentialFile, Basename) when is_binary(Message), is_binary(Basename)->
  {ok, SecretKey} = file:read_file(SecretKeyFile),
  {ok, Credential} = file:read_file(CredentialFile),
  ecdaa_do_sign(Message, SecretKey, Credential, Basename).


-spec ecdaa_do_sign(Message::binary(), SecretKey::binary(), Credential::binary(), Basename::binary()) -> signature().
ecdaa_do_sign(_,_,_,_)-> ok.
%%  erlang:nif_error(?LINE).

-spec ecdaa_do_sign(Message::binary(), SecretKey::binary(), Credential::binary()) -> signature().
ecdaa_do_sign(_,_,_)-> ok.
%%  erlang:nif_error(?LINE).