rule TTP_XOR_QUAD_CurrentVersionRun_c3bf {
  strings:
    $key_c3bf = { 90 d0 [2] b4 de [2] 9f f2 [2] b1 d0 [2] a5 cb [2] aa d1 [2] b4 cc [2] b6 cd [2] ad cb [2] b1 cc [2] ad e3 }

  condition:
    any of them
}