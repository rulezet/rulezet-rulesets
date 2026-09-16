rule sig_20160720_150f079832588dd4fa2ccf75c14cf5d9 {
  meta:
    description = "datamaliciousorder - file 20160720_150f079832588dd4fa2ccf75c14cf5d9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9088d314f37f76210c6c38d0b4ad8cf202bad17b681d3a6b0e0c18f05cd32fa4"

  strings:
    $x1  = "var x77 = new Array();function l97(o43,n47) { x77[n47] = o43; }; l97('      ', 492); function g76(o43,n47) { x77[n47] = o43; }; " ascii
    $s2  = "x77[n47] = o43; }; b84('.dll', 91); function o41(o43,n47) { x77[n47] = o43; }; o41('0);', 908); function u25(o43,n47) { x77[n47]" ascii
    $s3  = "'C% /c ', 758); function w30(o43,n47) { x77[n47] = o43; }; w30(' key.\"', 354); function n74(o43,n47) { x77[n47] = o43; }; n74('" ascii
    $s4  = "3('% /c D', 925); function c48(o43,n47) { x77[n47] = o43; }; c48(').\")', 680); function q39(o43,n47) { x77[n47] = o43; }; q39('" ascii
    $s5  = "2('C% /c ', 900); function i73(o43,n47) { x77[n47] = o43; }; i73('D \"+cq', 691); function v45(o43,n47) { x77[n47] = o43; }; v45" ascii
    $s6  = "43,n47) { x77[n47] = o43; }; l56(' - No', 607); function t47(o43,n47) { x77[n47] = o43; }; t47('eLi', 641); function l68(o43,n47" ascii
    $s7  = "47) { x77[n47] = o43; }; x55(' /y \"', 796); function z25(o43,n47) { x77[n47] = o43; }; z25('2);', 25); function e23(o43,n47) { " ascii
    $s8  = "= o43; }; z10('sktop', 676); function h13(o43,n47) { x77[n47] = o43; }; h13(' /t RE', 718); function c68(o43,n47) { x77[n47] = o" ascii
    $s9  = "43,n47) { x77[n47] = o43; }; n37('exce', 613); function c49(o43,n47) { x77[n47] = o43; }; c49('y /y ', 820); function n51(o43,n4" ascii
    $s10 = "5(o43,n47) { x77[n47] = o43; }; z55('  - I', 621); function v32(o43,n47) { x77[n47] = o43; }; v32('in', 890); function y92(o43,n" ascii
    $s11 = "', 17); function b98(o43,n47) { x77[n47] = o43; }; b98('TEMP%\"', 87); function m33(o43,n47) { x77[n47] = o43; }; m33('\"a', 77)" ascii
    $s12 = "7) { x77[n47] = o43; }; j40('.exe\",', 211); function d77(o43,n47) { x77[n47] = o43; }; d77('tware,', 635); function q52(o43,n47" ascii
    $s13 = "(o43,n47) { x77[n47] = o43; }; i66('e:\");', 403); function u32(o43,n47) { x77[n47] = o43; }; u32('Exi', 135); function p71(o43," ascii
    $s14 = "(o43,n47) { x77[n47] = o43; }; d52('q+', 903); function j64(o43,n47) { x77[n47] = o43; }; j64('re:\")', 445); function j40(o43,n" ascii
    $s15 = "= o43; }; r79('s.Run', 910); function l42(o43,n47) { x77[n47] = o43; }; l42('files.', 561); function j77(o43,n47) { x77[n47] = o" ascii
    $s16 = "x77[n47] = o43; }; u66('s\");', 332); function y71(o43,n47) { x77[n47] = o43; }; y71('.Run(\"', 726); function v12(o43,n47) { x7" ascii
    $s17 = " c58('s.Run(', 896); function o68(o43,n47) { x77[n47] = o43; }; o68('{ f', 147); function l64(o43,n47) { x77[n47] = o43; }; l64(" ascii
    $s18 = "U ', 595); function s59(o43,n47) { x77[n47] = o43; }; s59('\"%C', 923); function m86(o43,n47) { x77[n47] = o43; }; m86('s:\"', 4" ascii
    $s19 = "y82('a.wri', 193); function o61(o43,n47) { x77[n47] = o43; }; o61('COMS', 898); function l93(o43,n47) { x77[n47] = o43; }; l93('" ascii
    $s20 = "tion o39(o43,n47) { x77[n47] = o43; }; o39('d,2', 241); function o16(o43,n47) { x77[n47] = o43; }; o16('.Run', 815); function y3" ascii

  condition:
    uint16(0) == 0x6176 and
    1 of ($x*) and 4 of them
}