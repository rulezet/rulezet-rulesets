rule _20160921_962ed1e894cd91f421ad984310ce3140_20160921_be8454f98b5a_1741 {
  meta:
    description = "datamaliciousorder - from files 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_be8454f98b5a24b3ec56590bd13ee274.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash2       = "984696d2831d222abf66218ad54b440a2fd79bd47a7f1493a197576207321839"

  strings:
    $s1  = "(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";}" ascii
    $s2  = " \"We\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s3  = "(),(function fuck(){return \"Np\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s4  = "),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck()" ascii
    $s5  = "k(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"AUx" ascii
    $s6  = "turn \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})()," ascii
    $s7  = "ck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"YQt" ascii
    $s8  = "(){return \"USf\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\"" ascii
    $s9  = "Go\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s10 = "(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Dc\";})" ascii
    $s11 = "uck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"SUi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}