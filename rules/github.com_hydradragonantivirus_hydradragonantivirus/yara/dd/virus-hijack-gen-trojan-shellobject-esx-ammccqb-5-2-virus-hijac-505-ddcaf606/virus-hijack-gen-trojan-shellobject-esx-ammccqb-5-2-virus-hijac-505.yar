import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_505 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_9_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "94143e3c5b8bf576088fbdd4f8e39dabb3fa3deb0d3e54c9f019a0c50027f333"
    hash3       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash4       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"
    hash5       = "a51d302b290f4adb2da2151a0e108dc587a629823864d99310dcb2e56fb5feb3"

  strings:
    $s1  = " /></Sources><Group IgnoreErrors=\"true\" RecycleAction=\"TriggerOldest\"><Source Token=\"2\"><Field Name=\"RuleID\" /><Field Na" ascii
    $s2  = "4a10-93a0-2bc6273bc8e4}\" /><Filter Token=\"2\"><Operator Type=\"AND\"><Left><Operator Type=\"NE\"><Left><Source Token=\"1\" Fie" ascii
    $s3  = "</Column><Column OutType=\"UINT16\" Index=\"2\" Nullable=\"false\"><Source Token=\"2\" Field=\"RuleVersion\" /></Column><Column " ascii
    $s4  = "ng\" /></Left><Right><Constant Value=\"37\" OutType=\"UINT32\" /></Right></Operator></Left><Right><Operator Type=\"NE\"><Left><S" ascii
    $s5  = "oken=\"1\" Field=\"Warning\" /></Left><Right><Constant Value=\"29\" OutType=\"UINT32\" /></Right></Operator></Right></Operator><" ascii
    $s6  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><Rule RuleId=\"1000\" RuleVersion=\"5\" D" ascii
    $s7  = "<Timer Token=\"3\" Interval=\"10min\" /><AppEvent Token=\"4\" Event=\"TelemetrySuspend\" /><AppEvent Token=\"5\" Event=\"Telemet" ascii
    $s8  = "unt><Source Token=\"2\" /></Count></Column><Column OutType=\"UINT32\" Index=\"1\" Nullable=\"false\"><Source Token=\"2\" Field=" ascii
    $s9  = "INT8\" Index=\"3\" Nullable=\"false\"><Source Token=\"2\" Field=\"Warning\" /></Column><Column OutType=\"UINT64\" Index=\"4\" Nu" ascii
    $s10 = "Version\" /><Field Name=\"Warning\" /><Field Name=\"Info\" /></Source></Group><Column OutType=\"UINT32\" Index=\"0\" Nullable=\"" ascii
    $s11 = "\"><Source Token=\"2\" Field=\"Info\" /></Column><Triggers><Source Token=\"3\" /><Source Token=\"4\" /><Source Token=\"5\" /></T" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (8 of them)
    ) or (all of them)
}