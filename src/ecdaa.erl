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

-define(APPNAME, ecdaa).
-define(LIBNAME, 'ecdaa-erlang').

-on_load(init/0).

%% API
-export([
  priv_dir/0,
  sign/3,
  sign/4,
  do_sign/3,
  do_sign/4]).

-type signature() :: <<_:128>>.
-type message() :: [list() | binary()].
-type secret_key() :: [list() | binary()].
-type credential() :: [list() | binary()].
-type basename() :: [list() | binary() ].

init() ->
  SoName = filename:join([priv_dir(), ?LIBNAME]),
  erlang:load_nif(SoName, 0).

priv_dir() ->
  case code:priv_dir(?APPNAME) of
    {error, bad_name} ->
      case filelib:is_dir(filename:join(["..", priv])) of
        true ->
          filename:join(["..", priv]);
        _ -> "priv"
      end;
    Dir -> Dir
  end.

-spec sign(Message::message(), SecretKeyFile::secret_key(), CredentialFile::credential()) -> signature().
sign(MessageFile, SecretKeyFile, CredentialFile) when is_list(MessageFile) ->
  {ok, MessageBin} = file:read_file(MessageFile),
  sign(MessageBin, SecretKeyFile, CredentialFile);
sign(Message, SecretKeyFile, CredentialFile) when is_binary(Message), is_list(SecretKeyFile), is_list(CredentialFile) ->
  io:format("NO BASENAME SIGNING ~p with SK ~p and CRED ~p~n", [Message, SecretKeyFile, CredentialFile]),
  {ok, SecretKey} = file:read_file(SecretKeyFile),
  {ok, Credential} = file:read_file(CredentialFile),
  do_sign(Message, SecretKey, Credential).

do_sign(Message,SecretKey,Credential) when is_binary(Message), is_binary(SecretKey), is_binary(Credential)->
  erlang:nif_error(?LINE).

-spec sign(Message::message(), SecretKeyFile::secret_key(), CredentialFile::credential(), Basename::basename()) -> signature().
sign(MessageFile, SecretKeyFile, CredentialFile, Basename) when is_list(MessageFile)->
  {ok, MessageBin} = file:read_file(MessageFile),
  sign(MessageBin, SecretKeyFile, CredentialFile, Basename);
sign(Message, SecretKeyFile, CredentialFile, BasenameFile) when is_binary(Message), is_list(BasenameFile) ->
  {ok, BasenameBin} = file:read_file(BasenameFile),
  sign(Message, SecretKeyFile, CredentialFile, BasenameBin);
sign(Message, SecretKeyFile, CredentialFile, Basename) when is_binary(Message), is_binary(Basename)->
  io:format("BASENAME SIGNING ~p with SK ~p, CRED ~p, and BASENAME ~p~n", [Message, SecretKeyFile, CredentialFile, Basename]),
  {ok, SecretKey} = file:read_file(SecretKeyFile),
  {ok, Credential} = file:read_file(CredentialFile),
  do_sign(Message, SecretKey, Credential, Basename).

do_sign(Message,SecretKey,Credential,Basename) when is_binary(Message), is_binary(SecretKey), is_binary(Credential), is_binary(Basename)->
  erlang:nif_error(?LINE).


tpm_sign()->ok.



