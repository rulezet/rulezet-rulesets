rule _20160921_6ca29d2ebdcaa2724b801c02414faf7f_20160921_a56de0614f78_3884 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"
    hash2       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash3       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "tion f000(){return \"MDb\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return" ascii
    $s2 = "000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Oe" ascii
    $s3 = "{return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"SGs\";})" ascii
    $s4 = " f000(){return \"Nx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MD" ascii
    $s5 = "o\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s6 = "n \"Mc\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}