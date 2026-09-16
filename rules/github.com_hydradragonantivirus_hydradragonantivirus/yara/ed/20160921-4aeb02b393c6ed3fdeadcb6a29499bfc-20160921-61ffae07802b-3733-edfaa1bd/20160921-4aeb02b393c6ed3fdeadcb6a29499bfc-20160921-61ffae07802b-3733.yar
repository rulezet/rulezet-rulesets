rule _20160921_4aeb02b393c6ed3fdeadcb6a29499bfc_20160921_61ffae07802b_3733 {
  meta:
    description = "datamaliciousorder - from files 20160921_4aeb02b393c6ed3fdeadcb6a29499bfc.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_86f41d8c83240a68770674107f15f162.js, 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8899077a1617372e22229a59750fc04d1c9a0b2a1176b97742c5d76576a2edb1"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash3       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"
    hash4       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash5       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"

  strings:
    $s1 = "f000(){return \"MDb\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs" ascii
    $s2 = "\"BMj\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"RLk\";})(),(func" ascii
    $s3 = "(){return \"IPu\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s4 = "(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){r" ascii
    $s5 = "turn \"QDg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Iq\";})(),(f" ascii
    $s6 = "unction f000(){return \"Qa\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"MJq\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}