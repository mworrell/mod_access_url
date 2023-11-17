%% @author Marc Worrell <marc@worrell.nl>
%% @copyright 2022 Driebit BV
%% @doc Logon via an URL.

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

-module(controller_access_url).

-author("Marc Worrell <marc@worrell.nl>").

-export([
    init/1,
    service_available/2,
    allowed_methods/2,
    forbidden/2,
    resource_exists/2,
    previously_existed/2,
    moved_temporarily/2
]).

-include_lib("controller_webmachine_helper.hrl").
-include_lib("zotonic.hrl").

init(DispatchArgs) ->
    {ok, DispatchArgs}.

service_available(ReqData, DispatchArgs) when is_list(DispatchArgs) ->
    Context = z_context:new_request(ReqData, DispatchArgs, ?MODULE),
    {true, ReqData, Context}.

allowed_methods(ReqData, Context) ->
    {['GET'], ReqData, Context}.

forbidden(ReqData, Context) ->
    Context1 = ?WM_REQ(ReqData, Context),
    Context2 = z_context:ensure_all(Context1),
    Token = z_context:get_q("token", Context2),
    case m_access_url:decode_logon_token(Token, Context2) of
        {ok, UserId} ->
            % Logon user
            Context3 = z_context:set(user_id, UserId, Context2),
            case z_auth:logon(UserId, Context3) of
                {ok, ContextUser} ->
                    lager:info("Access token for ~p accepted", [ UserId ]),
                    ?WM_REPLY(false, ContextUser);
                {error, Reason} ->
                    lager:warning("Access token for ~p, error: ~p", [ UserId, Reason ]),
                    ?WM_REPLY(true, Context2)
            end;
        {error, Reason} ->
            lager:error("Access token not accepted: ~p", [ Reason ]),
            ?WM_REPLY(true, Context2)
    end.

resource_exists(ReqData, Context) ->
    {false, ReqData, Context}.

previously_existed(ReqData, Context) ->
    {true, ReqData, Context}.

moved_temporarily(ReqData, Context) ->
    Location = z_context:get_q("p", Context, ""),
    Location1 = z_context:site_url(Location, Context),
    {{true, Location1}, ReqData, Context}.
