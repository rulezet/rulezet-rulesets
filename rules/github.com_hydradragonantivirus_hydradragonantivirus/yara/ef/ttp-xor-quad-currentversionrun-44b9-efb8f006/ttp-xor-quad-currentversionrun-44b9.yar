rule TTP_XOR_QUAD_CurrentVersionRun_44b9 {
  strings:
    $key_44b9 = { 17 d6 [2] 33 d8 [2] 18 f4 [2] 36 d6 [2] 22 cd [2] 2d d7 [2] 33 ca [2] 31 cb [2] 2a cd [2] 36 ca [2] 2a e5 }

  condition:
    any of them
}