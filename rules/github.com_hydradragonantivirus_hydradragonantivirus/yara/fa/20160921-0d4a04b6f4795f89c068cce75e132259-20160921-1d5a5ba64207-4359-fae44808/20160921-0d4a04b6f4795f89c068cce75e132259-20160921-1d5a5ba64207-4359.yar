rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_1d5a5ba64207_4359 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash3       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash4       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash5       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"

  strings:
    $s1 = "n \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s2 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s3 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4 = "){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})" ascii
    $s5 = "Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}