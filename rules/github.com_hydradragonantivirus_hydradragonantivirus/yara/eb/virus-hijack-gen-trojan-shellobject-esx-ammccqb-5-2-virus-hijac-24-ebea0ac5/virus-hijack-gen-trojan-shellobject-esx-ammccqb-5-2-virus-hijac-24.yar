import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_24 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"

  strings:
    $x1  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><R Id=\"1000\" V=\"5\" DC=\"ESM\" EN=\"Of" ascii
    $s2  = "xternalData.Text\" T=\"W\" /></R></O></L><R><O T=\"AND\"><L><O T=\"NE\"><L><S T=\"5\" F=\"ScopeName\" /></L><R><V V=\"XLDesktop " ascii
    $s3  = "ution:532\" T=\"W\" /></R></O></L><R><O T=\"NE\"><L><S T=\"5\" F=\"ScopeName\" /></L><R><V V=\"XLDesktop Command Execution:534\"" ascii
    $s4  = "\"1\" F=\"ScopeName\" /></L><R><V V=\"XLDesktop Command Execution:534\" T=\"W\" /></R></O></L><R><O T=\"OR\"><L><O T=\"EQ\"><L><" ascii
    $s5  = "<L><S T=\"1\" F=\"ScopeName\" /></L><R><V V=\"XLDesktop Command Execution:532\" T=\"W\" /></R></O></L><R><O T=\"OR\"><L><O T=\"E" ascii
    $s6  = "__MOZCUSTOM__:campaign%3D%2528not%2Bset%2529%26content%3D%2528not%2Bset%2529%26medium%3Dreferral%26source%3Dwww.bing.com" fullword ascii
    $s7  = "CREATE TABLE events (record_id TEXT,tenant_token TEXT NOT NULL,latency INTEGER,persistence INTEGER,timestamp INTEGER,retry_count" ascii
    $s8  = " N=\"GetRelativePathsFailed\"><C><S T=\"18\" /></C></C><C T=\"W\" I=\"18\" O=\"true\" N=\"HashActualValue\"><S T=\"4\" F=\"Packa" ascii
    $s9  = " INTEGER DEFAULT 0,reserved_until INTEGER DEFAULT 0,payload BLOB)" fullword ascii
    $s10 = "ce.Extensibility.ODPInsertionDialog\" ATT=\"db334b301e7b474db5e0f02f07c51a47-a1b5bc36-1bbe-482f-a64a-c2d9cb606706-7439\" SP=\"Cr" ascii
    $s11 = "<description>7-Zip Self-extracting Archive v18.01</description>" fullword ascii
    $s12 = "><C T=\"W\" I=\"10\" O=\"true\"><S T=\"1\" F=\"ServiceId\" M=\"Ignore\" /></C><C T=\"I32\" I=\"11\" O=\"true\"><S T=\"1\" F=\"SH" ascii
    $s13 = " T=\"5\" F=\"LicenseType\" M=\"Ignore\" /></C><C T=\"B\" I=\"5\" O=\"true\" N=\"IsSubscription\"><S T=\"5\" F=\"AggregatedSubscr" ascii
    $s14 = "!!!!!fuk-tcpa!!!!!SQLite format 3" fullword ascii
    $s15 = "kernel:$DATv" fullword ascii
    $s16 = "der\" T=\"W\" /></C><C T=\"W\" I=\"7\" O=\"true\" N=\"ResultGroupArrangementOperation\"><S T=\"1\" F=\"Operation\" /></C><C T=\"" ascii
    $s17 = "able\" /><UCSS T=\"2\" C=\"Identity Accounts Control\" S=\"Monitorable\" /><UCSS T=\"3\" C=\"IdentityADALClient\" S=\"Monitorabl" ascii
    $s18 = "Text.WordUnknownGlyph.GlyphBasedRun\" ATT=\"9c9dcb87a41b41bebea94330a23d828d-35611aa0-46ca-4351-98e0-5746b84e5be3-6973\" SP=\"Cr" ascii
    $s19 = " /><UCSS T=\"8\" C=\"Identity Authentication CredSync\" S=\"Monitorable\" /><UCSS T=\"9\" C=\"Identity Authentication CredUtil\"" ascii
    $s20 = "rable\" /><UCSS T=\"12\" C=\"Identity Credentials Client\" S=\"Monitorable\" /><UCSS T=\"13\" C=\"Identity Critical Error\" S=\"" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}