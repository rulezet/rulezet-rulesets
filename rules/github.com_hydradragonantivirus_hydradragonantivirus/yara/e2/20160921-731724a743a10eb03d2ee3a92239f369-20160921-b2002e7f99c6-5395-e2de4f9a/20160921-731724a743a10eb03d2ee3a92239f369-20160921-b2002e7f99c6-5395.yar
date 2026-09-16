rule _20160921_731724a743a10eb03d2ee3a92239f369_20160921_b2002e7f99c6_5395 {
  meta:
    description = "datamaliciousorder - from files 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash2       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash3       = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "0(){return \"Iq\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"OUx\"" ascii
    $s2 = "n f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"M" ascii
    $s3 = ",(function f000(){return \"SGs\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Km\";})(),(function f000(){" ascii
    $s4 = " \"QDg\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(func" ascii
    $s5 = "n f000(){return \"Do\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}