import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_muZ_amBwvTb_9_1_Virus_Hijac_42 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.muZ@amBwvTb_9_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.mvZ@amBwvTb_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_12.vir, Virus.Hijack_Gen.Trojan.ShellObject.mWZ@aeFgVVo_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8178aa730e044365fcc4665f1bc4ffcf682d25cbb4e268cbdfd1e02a59e3a7b"
    hash2       = "6f2ea01918463d6c86c8675a48274811e2b0e3d6c4eff1cdddf8c0db301e8f4a"
    hash3       = "37365d2413fcc790064f20fb64b5793d0c17165ac5facf2fff4046de2c30059c"
    hash4       = "ddeffd2e61b7ae327d169af95750a1df48b3e11ffa954886a6690620a8ff1017"

  strings:
    $s1  = "?process_challenge@wamp_session@autobahn@@AAEX$$QAVwamp_message@6@@Z@@detail@boost@@@detail@boost@@" fullword ascii
    $s2  = "@?1??process_challenge@wamp_session@autobahn@@AAEX$$QAVwamp_message@6@@Z@@detail@boost@@@detail@boost@@" fullword ascii
    $s3  = "EVENT - SUBSCRIBED.Subscription must be an integer" fullword ascii
    $s4  = "SUBSCRIBED - SUBSCRIBED.Subscription must be an integer" fullword ascii
    $s5  = "EVENT - non-existent subscription ID " fullword ascii
    $s6  = "??process_challenge@wamp_session@autobahn@@AAEX$$QAVwamp_message@6@@Z@@detail@boost@@@detail@boost@@" fullword ascii
    $s7  = ".?AV?$thread_data@V?$bind_t@XP6AXV?$shared_ptr@Ushared_state_base@detail@boost@@@boost@@@ZV?$list1@V?$value@V?$shared_ptr@U?$fut" ascii
    $s8  = "invalid ERROR message structure - REQUEST.Request must be an integer" fullword ascii
    $s9  = "invalid ERROR message structure - ArgumentsKw must be a dictionary" fullword ascii
    $s10 = ".?AV?$enable_shared_from_this@V?$wamp_rawsocket_transport@V?$basic_stream_socket@Vtcp@ip@asio@boost@@V?$any_executor@U?$context_" ascii
    $s11 = ".?AV?$enable_shared_from_this@V?$wamp_rawsocket_transport@V?$basic_stream_socket@Vtcp@ip@asio@boost@@V?$any_executor@U?$context_" ascii
    $s12 = "invalid ERROR message structure - Details must be a dictionary" fullword ascii
    $s13 = ".?AV?$wamp_rawsocket_transport@V?$basic_stream_socket@Vtcp@ip@asio@boost@@V?$any_executor@U?$context_as_t@AAVexecution_context@a" ascii
    $s14 = ".?AV?$wamp_rawsocket_transport@V?$basic_stream_socket@Vtcp@ip@asio@boost@@V?$any_executor@U?$context_as_t@AAVexecution_context@a" ascii
    $s15 = "invalid ERROR message structure - REQUEST.Type must be an integer" fullword ascii
    $s16 = "invalid ERROR message structure - Arguments must be a list" fullword ascii
    $s17 = "invalid ERROR message structure - length must be 5, 6 or 7" fullword ascii
    $s18 = "invalid ERROR message - Error must be a string (URI)" fullword ascii
    $s19 = ".?AU?$future_sync_continuation_shared_state@V?$future@Vwamp_authenticate@autobahn@@@boost@@XV<lambda_1>@?1??process_challenge@wa" ascii
    $s20 = ".?AU?$future_deferred_continuation_shared_state@V?$future@Vwamp_authenticate@autobahn@@@boost@@XV<lambda_1>@?1??process_challeng" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "47d186778bc9d198554e460e0d3becb7" and (8 of them)
    ) or (all of them)
}