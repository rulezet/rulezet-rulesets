rule _20160921_38347709a1c3747cfb23ae60221ea7bf_20160921_50544c5faa56_781 {
  meta:
    description = "datamaliciousorder - from files 20160921_38347709a1c3747cfb23ae60221ea7bf.js, 20160921_50544c5faa56c0c9ed1c35075bafc583.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39473c48023f5000ce36bdc645860556dc6b5f3b0022f86190a49370f4633bbc"
    hash2       = "978b707f3e5da0fd4a8e7394863db19802410ff1b96376fc2432de59fafc5a69"

  strings:
    $s1  = " \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s2  = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return" ascii
    $s3  = "uck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py" ascii
    $s4  = "k(){return \"YQt\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt" ascii
    $s5  = "YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(functi" ascii
    $s6  = "ion fuck(){return \"PDf\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return" ascii
    $s7  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return" ascii
    $s8  = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s9  = "{return \"CTm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})" ascii
    $s10 = "ion fuck(){return \"To\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s11 = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ik\";})(),(function " ascii
    $s12 = "Pu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s13 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"XFd\";})(),(function fuck()" ascii
    $s14 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"" ascii
    $s15 = "{return \"PDf\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})" ascii
    $s16 = "return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s17 = ")(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck" ascii
    $s18 = "ction fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s19 = ",(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){" ascii
    $s20 = "uck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}