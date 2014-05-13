%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2014 Marc Worrell
%% @doc Access an url with the credentials of another user.

%% Copyright 2014 Marc Worrell
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


-module(mod_access_url).

-author("Marc Worrell <marc@worrell.nl>").

-mod_title("Access URL").
-mod_description("Sign an URL for an user so that it can be used for accessing vcal feeds etc.").

-export([
	observe_url_rewrite/3,
	observe_request_context/3
	]).

-include_lib("zotonic.hrl").

observe_url_rewrite(#url_rewrite{dispatch=Dispatch, args=Args}, Url, Context) ->
	case proplists:get_value(z_access_url, Args) of
		true ->
			maybe_add_token(Dispatch, Args, Url, Context);
		_ ->
			Url
	end.

observe_request_context(request_context, Context, _Context) ->
	case z_auth:is_auth(Context) of
		false ->
			case z_convert:to_bool(z_context:get_q("z_access_url", Context)) of
				true ->
					sudo_if_sigok(Context);
				false ->
					Context
			end;
		true ->
			Context
	end.

maybe_add_token(Dispatch, Args, Url, Context) ->
	case z_acl:user(Context) of
		undefined ->
			Url;
		UserId when is_integer(UserId) ->
			{ok, Token, Secret} = user_secret(UserId, Context),
			Nonce = z_convert:to_binary(z_ids:id()),
			Sig = sign(Dispatch, Args, Token, Nonce, Secret),
			Sig1 = z_convert:to_binary(z_utils:url_encode(Sig)),
			<<Url/binary,
				"&z_access_url_token=", Token/binary,
				"&z_access_url_nonce=", Nonce/binary,
				"&z_access_url_sig=", Sig1/binary>>
	end.

user_secret(UserId, Context) ->
	case m_identity:get_rsc_by_type(UserId, ?MODULE, Context) of
		[] ->
			Token = z_convert:to_binary(z_ids:id(20)),
			Secret = z_convert:to_binary(z_ids:id(40)),
			m_identity:insert(UserId, ?MODULE, Token, [{prop1, Secret}], Context),
			{ok, Token, Secret};
		[Idn|_] ->
			Token = proplists:get_value(key, Idn),
			Secret = proplists:get_value(prop1, Idn),
			{ok, Token, Secret} 
	end.

token_user(Token, Context) ->
	case m_identity:lookup_by_type_and_key(?MODULE, Token, Context) of
		undefined ->
			{error, enoent};
		Idn when is_list(Idn) ->
			UserId = proplists:get_value(rsc_id, Idn),
			Secret = proplists:get_value(prop1, Idn),  
			{ok, UserId, Secret}
	end.

sudo_if_sigok(Context) ->
	Token = z_convert:to_binary(z_context:get_q(z_access_url_token, Context)),
	case token_user(Token, Context) of
		{ok, UserId, Secret} ->
			Nonce = z_context:get_q(z_access_url_nonce, Context),
			Dispatch = z_context:get_q(zotonic_dispatch, Context),
			Sig = z_convert:to_binary(z_context:get_q(z_access_url_sig, Context)),
			case sign(Dispatch, z_context:get_q_all_noz(Context), Token, Nonce, Secret) of
				Sig ->
					z_acl:logon(UserId, Context);
				_Other ->
					lager:warning("Non matching sign on request ~p", [wrq:raw_path(z_context:get_reqdata(Context))]),
					Context
			end;
		{error, enoent} ->
			lager:info("Unknown url_access_token \"~p\"", [Token]),
			Context
	end.

sign(Dispatch, Args, Token, Nonce, Secret) ->
	Args1 = filter_args(Args, []),
	Data = term_to_binary([
					Args1,
					signed, 
					z_convert:to_binary(Dispatch),
					z_convert:to_binary(Nonce),
					z_convert:to_binary(Token),
					z_convert:to_binary(Secret)
				]),
     base64:encode(crypto:hash(sha256, Data)).

filter_args([], Acc) ->
	lists:sort(Acc);
filter_args([Token|Args], Acc) when is_atom(Token) ->
	filter_args([{Token,<<"true">>}|Args], Acc);
filter_args([{"z_access_url"++_,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{<<"z_access_url", _/binary>>,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{"z_language",_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{"zotonic_"++_,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{<<"z_language">>,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{<<"zotonic_", _/binary>>,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{z_language,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{zotonic_dispatch,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{zotonic_dispatch_path,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{zotonic_dispatch_path_rewrite,_}|Args], Acc) ->
	filter_args(Args, Acc);
filter_args([{K,V}|Args], Acc) ->
	K1 = z_convert:to_binary(K),
	case K1 of
		<<"z_access_url", _/binary>> ->
			filter_args(Args, Acc);
		_ ->
			V1 = z_convert:to_binary(V), 
			filter_args(Args, [{K1,V1}|Acc])
	end.