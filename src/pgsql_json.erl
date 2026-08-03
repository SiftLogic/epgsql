-module(pgsql_json).

-export([encode/1, decode/1]).

-define(IPV4_REGEX, <<"^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$">>).
-define(IPV6_REGEX, <<"^([0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::|([0-9a-fA-F]{1,4}:){1,7}:|:([0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4}$">>).
-define(IPV4_CIDR_REGEX, <<"^([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})\\/(3[0-2]|[12]?[0-9])$">>).
-define(IPV6_CIDR_REGEX, <<"^((?:[0-9a-fA-F]{1,4}:){1,7}[0-9a-fA-F]{1,4}|::|(?:[0-9a-fA-F]{1,4}:){1,7}:|:(?:[0-9a-fA-F]{1,4}:){1,6}[0-9a-fA-F]{1,4})\\/(128|[1-7][0-9]|[1-9]?[0-9])$">>).


encode([]) ->
    <<"[]">>;
encode(<<>>) ->
    <<"\"\"">>;
encode(#{} = Map) when map_size(Map) =:= 0 ->
    <<"{}">>;
encode(null) ->
    null;
encode(Map) when is_map(Map) ->
    iolist_to_binary(json:encode(Map, fun json_encoder/2));
encode(Map) when is_list(Map) ->
    try json:encode(Map, fun json_encoder/2) of
        Json ->
            iolist_to_binary(Json)
    catch
        _E:_M ->
            error_logger:error_msg(
                "json_encode: Invalid term ~p",
                [Map]
            ),
            throw({badarg, invalid_json})
    end;
encode(Term) ->
    error_logger:error_msg(
        "json_encode: Invalid term ~p",
        [Term]
    ),
    throw({badarg, invalid_json}).

decode(null) ->
    null;
decode(<<"{}">>) ->
    #{};
decode(<<"[]">>) ->
    [];
decode(<<"\"\"">>) ->
    <<>>;
decode(Term) when is_binary(Term) ->
    {Res, ok, _} = json:decode(Term, ok, #{object_push => fun decoder_object_push/3,
                                           array_push => fun decoder_array_push/2,
                                           float => fun(V) -> V end}),
    Res;
decode(Term) ->
    error_logger:error_msg(
        "json_decode: Invalid term ~p",
        [Term]
    ),
    throw({error, invalid_json}).

json_encoder([{_, _} | _] = Value, Encode) ->
    %% encoder for proplist
    json:encode_key_value_list(Value, Encode);
json_encoder({{Yr,Mon,Day}, {Hr, Min, Sec0}}, Encode) when is_integer(Yr) andalso is_integer(Mon) andalso is_integer(Day) andalso is_integer(Hr) andalso is_integer(Min) andalso is_number(Sec0) ->
    %% encoder for datetime
    Sec = case Sec0 < 10 of
        true -> <<"0", (float_to_binary(Sec0 * 1.0, [{decimals, 6}, compact]))/binary>>;
        false -> float_to_binary(Sec0 * 1.0, [{decimals, 6}, compact])
    end,
    json:encode_value(iolist_to_binary(io_lib:format(
        "~4..0b-~2..0b-~2..0b ~2..0b:~2..0b:~s",
        [Yr, Mon, Day, Hr, Min, Sec]
    )), Encode);
json_encoder({Yr,Mon,Day}, Encode) when is_integer(Yr) andalso Yr >= 1800 andalso Yr < 3000 andalso is_integer(Mon) andalso is_integer(Day) ->
    %% encoder for date
    json:encode_value(json:encode_value(iolist_to_binary(io_lib:format(
        "~4..0b-~2..0b-~2..0b",
        [Yr, Mon, Day]
    )), Encode), Encode);
json_encoder({Hr, Min, Sec}, Encode) when is_integer(Hr) andalso Hr >= 0 andalso Hr < 24 andalso is_integer(Min) andalso Min >= 0 andalso Min < 60 andalso is_number(Sec) ->
    %% encoder for time
    json:encode_value(iolist_to_binary(io_lib:format("~2..0B:~2..0B:~2..0B", [Hr, Min, Sec])), Encode);
json_encoder({A,B,C,D} = Ip, Encode) when
    is_integer(A) andalso A >= 0 andalso A < 256 andalso
    is_integer(B) andalso B >= 0 andalso B < 256 andalso
    is_integer(C) andalso C >= 0 andalso C < 256 andalso
    is_integer(D) andalso D >= 0 andalso D < 256 ->
    %% encoder for IPv4 address
    json:encode_value(iolist_to_binary(inet_parse:ntoa(Ip)), Encode);
json_encoder({{A,B,C,D} = Ip, Netmask}, Encode) when
    is_integer(A) andalso A >= 0 andalso A < 256 andalso
    is_integer(B) andalso B >= 0 andalso B < 256 andalso
    is_integer(C) andalso C >= 0 andalso C < 256 andalso
    is_integer(D) andalso D >= 0 andalso D < 256 andalso
    is_integer(Netmask) andalso Netmask >= 0 andalso Netmask < 128 ->
    %% encoder for IPv4 address with netmask
    json:encode_value(iolist_to_binary(io_lib:format("~s/~B", [inet_parse:ntoa(Ip), Netmask])), Encode);
json_encoder({A,B,C,D,E,F,G,H} = Ipv6, Encode) when
    is_integer(A) andalso A >= 0 andalso A < 65536 andalso
    is_integer(B) andalso B >= 0 andalso B < 65536 andalso
    is_integer(C) andalso C >= 0 andalso C < 65536 andalso
    is_integer(D) andalso D >= 0 andalso D < 65536 andalso
    is_integer(E) andalso E >= 0 andalso E < 65536 andalso
    is_integer(F) andalso F >= 0 andalso F < 65536 andalso
    is_integer(G) andalso G >= 0 andalso G < 65536 andalso
    is_integer(H) andalso H >= 0 andalso H < 65536 ->
    %% encoder for IPv6 address
    json:encode_value(iolist_to_binary(inet_parse:ntoa(Ipv6)), Encode);
json_encoder({{A,B,C,D,E,F,G,H} = Ipv6, Netmask}, Encode) when
    is_integer(A) andalso A >= 0 andalso A < 65536 andalso
    is_integer(B) andalso B >= 0 andalso B < 65536 andalso
    is_integer(C) andalso C >= 0 andalso C < 65536 andalso
    is_integer(D) andalso D >= 0 andalso D < 65536 andalso
    is_integer(E) andalso E >= 0 andalso E < 65536 andalso
    is_integer(F) andalso F >= 0 andalso F < 65536 andalso
    is_integer(G) andalso G >= 0 andalso G < 65536 andalso
    is_integer(H) andalso H >= 0 andalso H < 65536 andalso
    is_integer(Netmask) andalso Netmask >= 0 andalso Netmask < 128 ->
    %% encoder for IPv6 address with netmask
    json:encode_value(iolist_to_binary(io_lib:format("~s/~B", [inet_parse:ntoa(Ipv6), Netmask])), Encode);
json_encoder(Other, Encode) ->
    %% encoder for other types
    json:encode_value(Other, Encode).

%% decoder: use custom functions to mirror the json_encoder function
decoder_object_push(Key, <<_:4/binary, "-", _:2/binary, "-", _:2/binary, Sep:1/binary, _:2/binary, ":", _:2/binary, ":",
        _:2/binary, _TZData/binary>> = DateTimeBin, Acc) when Sep =:= <<" ">> orelse Sep =:= <<"T">> ->
            try qdate:to_date(DateTimeBin) of
            {_, {_, _, _}} = Dt0 ->
                [{Key, Dt0} | Acc];
            {D0, {H0, M0, S0, Ms}} ->
                [{Key, {D0, {H0, M0, S0 + (Ms / 1_000_000)}}} | Acc]
            catch
                E:M:St ->
                  logger:error("Invalid datetime [~p]: ~p ~p", [Key, DateTimeBin, {E,M,St}]),
                  [{Key, DateTimeBin} | Acc]
            end;
decoder_object_push(Key, <<Y1, Y2, Y3, Y4, "-", M1, M2, "-", D1, D2>> = DateBin, Acc) when
    Y1 >= $0, Y1 =< $9,
    Y2 >= $0, Y2 =< $9,
    Y3 >= $0, Y3 =< $9,
    Y4 >= $0, Y4 =< $9,
    M1 >= $0, M1 =< $9,
    M2 >= $0, M2 =< $9,
    D1 >= $0, D1 =< $9,
    D2 >= $0, D2 =< $9 ->
    %% date decoder
    try qdate:to_date(DateBin) of
        {Date, _} ->
            [{Key, Date} | Acc]
    catch
        E:M:St ->
            logger:error("Invalid date [~p]: ~p ~p", [Key, DateBin, {E,M,St}]),
            [{Key, DateBin} | Acc]
    end;
decoder_object_push(Key, Val0, Acc) when is_binary(Val0) ->
    case chk_ip_or_cidr(Val0) of
        {true, IpOrCidr} ->
            [{Key, IpOrCidr} | Acc];
        false ->
            [{Key, Val0} | Acc]
    end;
decoder_object_push(Key, Val0, Acc) ->
    %% for other types, just return the value
    [{Key, Val0} | Acc].

decoder_array_push(<<_:4/binary, "-", _:2/binary, "-", _:2/binary, Sep:1/binary, _:2/binary, ":", _:2/binary, ":",
        _:2/binary, _TZData/binary>> = DateTimeBin, Acc) when Sep =:= <<" ">> orelse Sep =:= <<"T">> ->
    try qdate:to_date(DateTimeBin) of
        {_, {_, _, _}} = Dt0 ->
            [Dt0 | Acc];
        {D0, {H0, M0, S0, Ms}} ->
            [{D0, {H0, M0, S0 + (Ms / 1_000_000)}} | Acc]
    catch
        E:M:St ->
            logger:error("Invalid datetime in array: ~p ~p", [DateTimeBin, {E,M,St}]),
            Acc
    end;
decoder_array_push(<<Y1, Y2, Y3, Y4, "-", M1, M2, "-", D1, D2>> = DateBin, Acc) when
    Y1 >= $0, Y1 =< $9,
    Y2 >= $0, Y2 =< $9,
    Y3 >= $0, Y3 =< $9,
    Y4 >= $0, Y4 =< $9,
    M1 >= $0, M1 =< $9,
    M2 >= $0, M2 =< $9,
    D1 >= $0, D1 =< $9,
    D2 >= $0, D2 =< $9 ->
    %% date decoder
    try qdate:to_date(DateBin) of
        {Date, _} ->
            [Date | Acc]
    catch
        E:M:St ->
            logger:error("Invalid date in array: ~p ~p", [DateBin, {E,M,St}]),
            Acc
    end;
decoder_array_push(Val0, Acc) when is_binary(Val0) ->
    case chk_ip_or_cidr(Val0) of
        {true, IpOrCidr} ->
            [IpOrCidr | Acc];
        false ->
            [Val0 | Acc]
    end;
decoder_array_push(Val0, Acc) ->
    %% for other types, just return the value
    [Val0 | Acc]. 

regex(Name, Pattern, Options) ->
    case persistent_term:get(Name, undefined) of
        undefined ->
            %% -type nl_spec() :: cr | crlf | lf | anycrlf | any.
            %% -type compile_option() :: unicode | anchored | caseless | dollar_endonly
            %%             | dotall | extended | firstline | multiline
            %%             | no_auto_capture | dupnames | ungreedy
            %%             | {newline, nl_spec()}
            %%             | bsr_anycrlf | bsr_unicode
            %%             | no_start_optimize | ucp | never_utf.
            {ok, Regex} = re:compile(Pattern, Options),
            persistent_term:put(Name, Regex),
            Regex;
        Regex ->
            Regex
    end.

chk_ip_or_cidr(Val0) ->
    Ipv4 = regex({?MODULE, chk_ipv4}, ?IPV4_REGEX, []),
    Ipv6 = regex({?MODULE, chk_ipv6}, ?IPV6_REGEX, []),
    case re:run(Val0, Ipv4, [{capture, none},global]) =:= match orelse
        re:run(Val0, Ipv6, [{capture, none},global]) =:= match of
        true ->
            case inet:parse_address(binary_to_list(Val0)) of
                {ok, Ip} ->
                    {true, Ip};
                _ ->
                    false
            end;
        false ->
            Ipv4Cidr = regex({?MODULE, chk_ipv4_cidr}, ?IPV4_CIDR_REGEX, []),
            case re:run(Val0, Ipv4Cidr, [{capture, all_but_first, list}, global]) of
                {match, [Ip, Netmask]} ->
                    case inet:parse_address(Ip) of
                        {ok, IpAddr} ->
                            {true, {IpAddr, list_to_integer(Netmask)}};
                        _ ->
                            false
                    end;
                nomatch ->
                    Ipv6Cidr = regex({?MODULE, chk_ipv6_cidr}, ?IPV6_CIDR_REGEX, []),
                    case re:run(Val0, Ipv6Cidr, [{capture, all_but_first, list}, global]) of
                        {match, [Ip, Netmask]} ->
                            case inet:parse_address(Ip) of
                                {ok, IpAddr} ->
                                    {true, {IpAddr, list_to_integer(Netmask)}};
                                _ ->
                                    false
                            end;
                        nomatch ->
                            false
                    end
            end
    end.
