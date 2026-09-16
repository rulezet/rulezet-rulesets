rule HKTL_NET_GUID_Xploit {
    meta:
        description = "Detects c# red/black-team tools via typelibguid"
        reference = "https://github.com/shargon/Xploit"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Arnim Rupp (https://github.com/ruppde)"
        date = "2020-12-21"
        modified = "2025-08-15"
        id = "11ba6c14-06b6-5d9f-ac69-08ae506877e7"
    strings:
        $typelibguid0lo = "4545cfde-9ee5-4f1b-b966-d128af0b9a6e" ascii wide
        $typelibguid1lo = "33849d2b-3be8-41e8-a1e2-614c94c4533c" ascii wide
        $typelibguid2lo = "c2dc73cc-a959-4965-8499-a9e1720e594b" ascii wide
        $typelibguid3lo = "77059fa1-4b7d-4406-bc1a-cb261086f915" ascii wide
        $typelibguid4lo = "a4a04c4d-5490-4309-9c90-351e5e5fd6d1" ascii wide
        $typelibguid5lo = "ca64f918-3296-4b7d-9ce6-b98389896765" ascii wide
        $typelibguid6lo = "10fe32a0-d791-47b2-8530-0b19d91434f7" ascii wide
        $typelibguid7lo = "679bba57-3063-4f17-b491-4f0a730d6b02" ascii wide
        $typelibguid8lo = "0981e164-5930-4ba0-983c-1cf679e5033f" ascii wide
        $typelibguid9lo = "2a844ca2-5d6c-45b5-963b-7dca1140e16f" ascii wide
        $typelibguid10lo = "7d75ca11-8745-4382-b3eb-c41416dbc48c" ascii wide
    condition:
        (uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550) and any of them
}