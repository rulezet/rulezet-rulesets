rule _20160921_22fd683e7973fc938e9d6980e5e81789_20160921_3065f95fdd47_468 {
  meta:
    description = "datamaliciousorder - from files 20160921_22fd683e7973fc938e9d6980e5e81789.js, 20160921_3065f95fdd47a96a00f0692965111ae8.js, 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_ee6d5c7dc2c03b89ea5ef53aa0c676a1.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3583ada9b0a35137add948ee4bd3182a5f977a0dbcc3a39c01ee288f703d566"
    hash2       = "78116ceaf58fe5711732c6fa5c646094dd87471f2d3ce65adbd7b478d5bbc1bb"
    hash3       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash4       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash5       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash6       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash7       = "ddd3db3929119812b70ad9f62bd3187b6108d24999c41a8ff5390bc9a60387a3"
    hash8       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "n \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(func" ascii
    $s2  = "urn \"Jo\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3  = "fuck(){return \"Pc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu" ascii
    $s4  = "){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"We\";})(" ascii
    $s5  = " \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Av\";})(),(func" ascii
    $s6  = "Vh\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s7  = "urn \"Xg\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s8  = "uck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ar\"" ascii
    $s9  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s10 = "){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";}" ascii
    $s11 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"" ascii
    $s12 = "n fuck(){return \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"" ascii
    $s13 = "IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(functi" ascii
    $s14 = "),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){r" ascii
    $s15 = "urn \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xw\";})(),(f" ascii
    $s16 = "n fuck(){return \"XHj\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"" ascii
    $s17 = "eturn \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s18 = "function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){r" ascii
    $s19 = "k(){return \"Wn\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})" ascii
    $s20 = "return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"DWe\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}