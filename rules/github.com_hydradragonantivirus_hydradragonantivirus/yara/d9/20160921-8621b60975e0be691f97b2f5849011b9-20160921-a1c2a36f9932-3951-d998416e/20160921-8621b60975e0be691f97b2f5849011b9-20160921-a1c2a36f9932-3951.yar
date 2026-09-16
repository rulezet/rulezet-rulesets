rule _20160921_8621b60975e0be691f97b2f5849011b9_20160921_a1c2a36f9932_3951 {
  meta:
    description = "datamaliciousorder - from files 20160921_8621b60975e0be691f97b2f5849011b9.js, 20160921_a1c2a36f99325740dcba8c8ff770ac3f.js, 20160921_a977d2870f5e9d12c659565b82cfaa70.js, 20160921_c6572694e5172932491036c67fc9ffe4.js, 20160921_fd5fc067457571e92a95bd16158d41e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "937753c3d12421c3fdd542dbca838c421a31dea2d960a14b5b2bd7617f8d3ec0"
    hash2       = "fd45dd180ae2e467969ca65317708ffe88d107b19f9f1b433b6c271c63c4fc6f"
    hash3       = "53eed08aece7cc2a81b9828098c3d3e70042a4891863f1130086a0661fc12870"
    hash4       = "e6ae2536ba0486138837b2ae1457fd029e88f0c21975b726f4edd05ba182b08e"
    hash5       = "e32ed831874bb280ae970e019573b598cf97788865b3fea13118546e435353f9"

  strings:
    $s1 = "f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"T" ascii
    $s2 = "n \"UOt\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(f" ascii
    $s3 = "f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GG" ascii
    $s4 = "n \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(fun" ascii
    $s5 = "00(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc" ascii
    $s6 = "00(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}