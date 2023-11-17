%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2022 Driebit BV
%% @doc Filter to make an access url

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

-module(filter_access_url).

-export([
    access_url/2,
    access_url/3
]).

access_url(Url, Context) ->
    access_url(Url, 3600, Context).

access_url(Url, Secs, Context) ->
    try
        Url1 = z_string:trim(iolist_to_binary(Url)),
        Seconds = z_convert:to_integer(Secs),
        case m_access_url:encode_logon_token(z_acl:user(Context), Seconds, Context) of
            {ok, Token} ->
                RUrl = z_dispatcher:url_for(access_url, [ {token, Token}, {p, Url1} ], Context),
                z_context:abs_url(RUrl, Context);
            {error, _} ->
                <<>>
        end
    catch
        _:_ ->
            lager:warning("access_url filter on non iodata: ~p", [ Url ]),
            <<>>
    end.

