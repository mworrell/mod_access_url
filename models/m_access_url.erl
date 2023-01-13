%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2022 Driebit BV
%% @doc Model for creating access urls.

%% Copyright 2022 Driebit BV
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(m_access_url).

-export([
    m_find_value/3,
    m_to_list/2,
    m_value/2,

    decode_logon_token/2,
    encode_logon_token/3,
    config_secret/1,
    user_secret/2
]).

-define(AUTH_SECRET_LENGTH, 20).

-include("zotonic.hrl").

m_find_value(token, #m{ value = undefined } = M, _Context) ->
    M#m{ value = token };
m_find_value(Secs, #m{ value = token }, Context) when is_integer(Secs) ->
    case z_acl:user(Context) of
        undefined ->
            undefined;
        UserId ->
            case encode_logon_token(UserId, Secs, Context) of
                {ok, Token} -> Token;
                {error, _} -> undefined
            end
    end.

m_to_list(#m{}, _Context) ->
    [].

m_value(#m{ value = token } = M, Context) ->
    m_find_value(3600, M, Context).

-spec decode_logon_token(binary()|string(), z:context()) -> {ok, m_rsc:resource_id()} | {error, term()}.
decode_logon_token(Token, Context) when is_binary(Token) ->
    {ok, ConfigSecret} = config_secret(Context),
    Now = z_datetime:timestamp(),
    case termit:decode_base64(Token, ConfigSecret) of
        {ok, {u, TokenUserId, TokenUserSecret, Exp}} when Exp >= Now ->
            case user_secret(TokenUserId, Context) of
                {ok, UserSecret} ->
                    case eq(UserSecret, TokenUserSecret) of
                        true -> {ok, TokenUserId};
                        false -> {error, forged}
                    end;
                {error, _} = Error ->
                    Error
            end;
        {ok, {u, _, _, _Exp}} ->
            {error, expired};
        {error, _} = Error ->
            Error
    end;
decode_logon_token(Token, Context) ->
    decode_logon_token(z_convert:to_binary(Token), Context).

-spec encode_logon_token(m_rsc:resource_id(), integer(), z:context()) -> {ok, binary()} | {error, term()}.
encode_logon_token(UserId, Seconds, Context) when is_integer(UserId) ->
    case m_rsc:p(UserId, is_published_date, Context) of
        true ->
            case user_secret(UserId, Context) of
                {ok, UserSecret} ->
                    {ok, ConfigSecret} = config_secret(Context),
                    Term = {u, UserId, UserSecret, z_datetime:timestamp() + Seconds},
                    Token = termit:encode_base64(Term, ConfigSecret),
                    {ok, Token};
                {error, _} = Error ->
                    Error
            end;
        false ->
            {error, unpublished}
    end.

-spec config_secret(z:context()) -> {ok, binary()}.
config_secret(Context) ->
    case m_config:get_value(mod_access_url, url_logon_secret, Context) of
        undefined ->
            Secret = z_convert:to_binary(z_ids:id(?AUTH_SECRET_LENGTH)),
            m_config:set_value(mod_access_url, url_logon_secret, Secret, Context),
            {ok, Secret};
        Secret when is_binary(Secret) ->
            {ok, Secret}
    end.

-spec user_secret( m_rsc:resource_id() | undefined, z:context() ) -> {ok, binary()} | {error, enoent}.
user_secret(UserId, Context) ->
    case m_rsc:exists(UserId, Context) of
        true ->
            case m_identity:get_rsc(UserId, auth_secret, Context) of
                undefined -> generate_user_secret(UserId, Context);
                Idn -> {ok, proplists:get_value(prop1, Idn)}
            end;
        false ->
            {error, enoent}
    end.

-spec generate_user_secret( m_rsc:resource_id(), z:context() ) -> binary().
generate_user_secret(UserId, Context) ->
    Secret = z_convert:to_binary(z_ids:id(?AUTH_SECRET_LENGTH)),
    {ok, _} = m_identity:insert(UserId, auth_secret, <<>>, [{prop1, Secret}], Context),
    {ok, Secret}.

%% @doc Compare for equality in consistent time.
eq(A, B) ->
    eq1(A, B, true).

eq1(<<>>, <<>>, Eq) -> Eq;
eq1(<<>>, _, _Eq) -> false;
eq1(_, <<>>, _Eq) -> false;
eq1(<<A,RA/binary>>, <<B,RB/binary>>, Eq) ->
    eq1(RA, RB, A =:= B andalso Eq).
