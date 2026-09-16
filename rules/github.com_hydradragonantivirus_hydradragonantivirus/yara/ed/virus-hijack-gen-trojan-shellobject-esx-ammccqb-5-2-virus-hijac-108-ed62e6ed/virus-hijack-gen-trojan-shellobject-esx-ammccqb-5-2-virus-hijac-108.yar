import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_5_2_Virus_Hijac_108 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23a25cc2feec851e0d1dbcb3edabe0d02373f176b4526cdb3abd97795b5a5c4d"
    hash2       = "c7f9226d258791bc3b7c2459e2e1764be913a0985a60ca6bcd67fadbbaf5462c"
    hash3       = "ba64fce50534b1583891982a16956c9a24ae91daea1668605d102620b6677b2d"

  strings:
    $x1  = "!!!!!fuk-tcpa!!!!!<?xml version=\"1.0\" encoding=\"utf-8\"?><Rules xmlns=\"urn:Rules\"><Rule RuleId=\"1000\" RuleVersion=\"5\" D" ascii
    $s2  = "ue=\"TellMeD_ExecutedCommand\" OutType=\"WSTRING\" /></Column><Column OutType=\"WSTRING\" Index=\"10\" Nullable=\"true\"><Source" ascii
    $s3  = "le=\"true\"><UnaryOperator Type=\"OneWaySHA1HashToBinary\"><Source Token=\"1\" Field=\"ComputerSystemProductId\" MissingFieldHan" ascii
    $s4  = "ns=\"SM\" Target=\"Subrule\" xmlns=\"\"><Sources><RuleSource Token=\"1\" RuleId=\"11662\" /><Filter Token=\"2\"><Operator Type=" ascii
    $s5  = "cations=\"ESM\" Target=\"Upload-Medium\" xmlns=\"\"><Sources><ULSTagSource Token=\"1\" StringTagId=\"a1juv\" /><Filter Token=\"2" ascii
    $s6  = "umn><Triggers><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"68017\" RuleVersion=\"1\" DataClassifications=\"SM\" Target" ascii
    $s7  = "Token=\"2\" Field=\"ProcessFileName\" /></Column><Column OutType=\"BOOL\" Index=\"10\" Nullable=\"true\"><Source Token=\"2\" Fie" ascii
    $s8  = "e=\"true\"><Source Token=\"1\" Field=\"ProcessorCount\" MissingFieldHandling=\"Ignore\" /></Column><Column OutType=\"UINT32\" In" ascii
    $s9  = "aProcessingLimit\" MissingFieldHandling=\"Ignore\" /></Column><Triggers><Source Token=\"2\" /></Triggers></Rule><Rule RuleId=\"1" ascii
    $s10 = "lumn OutType=\"UINT32\" Index=\"5\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessorFrequency\" MissingFieldHandling=\"Ig" ascii
    $s11 = "lumn></Rule><Rule RuleId=\"10300\" RuleVersion=\"1\" DataClassifications=\"ESM\" Target=\"Upload\" xmlns=\"\"><Sources><AppEvent" ascii
    $s12 = "ssorCount\" /></Column><Column OutType=\"UINT32\" Index=\"15\" Nullable=\"true\"><Source Token=\"3\" Field=\"ProcessorFrequency" ascii
    $s13 = "><Source Token=\"4\" /></Starts></Rule><Rule RuleId=\"120120\" RuleVersion=\"0\" DataClassifications=\"ESM\" Target=\"Upload\" x" ascii
    $s14 = "Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessFileName\" MissingFieldHandling=\"Ignore\" /></Column><Column OutType=\"BOO" ascii
    $s15 = "ld=\"CommandActionType\" /></Column><Triggers><Source Token=\"1\" /></Triggers></Rule><Rule RuleId=\"322006\" RuleVersion=\"5\" " ascii
    $s16 = "Token=\"1\" /></Triggers></Rule><Rule RuleId=\"68016\" RuleVersion=\"1\" DataClassifications=\"SM\" Target=\"Upload\" xmlns=\"\"" ascii
    $s17 = "\"3\" Field=\"ProcessorArchitecture\" /></Column><Column OutType=\"UINT32\" Index=\"14\" Nullable=\"false\"><Source Token=\"3\" " ascii
    $s18 = "umn OutType=\"WSTRING\" Index=\"15\" Nullable=\"true\"><Source Token=\"1\" Field=\"ProcessFileName\" MissingFieldHandling=\"Igno" ascii
    $s19 = "rs><Source Token=\"3\" /></Triggers></Rule><Rule RuleId=\"68004\" RuleVersion=\"13\" DataClassifications=\"SM\" Target=\"Upload" ascii
    $s20 = "urce Token=\"1\" Field=\"ProcessorArchitecture\" MissingFieldHandling=\"Ignore\" /></Column><Column OutType=\"UINT32\" Index=\"1" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "98dfd9b9e184a03c6ea488ca38f4797e" and (1 of ($x*) and 4 of them)
    ) or (all of them)
}