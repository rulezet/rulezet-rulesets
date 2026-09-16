rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_61ffae07802b_4881 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"

  strings:
    $s1 = "ction f000(){return \"Sv\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"DYx\";})(),(function f000(){return" ascii
    $s2 = "b\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"PTs\";})(),(functio" ascii
    $s3 = "return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})" ascii
    $s4 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return" ascii
    $s5 = "return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DYx\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}