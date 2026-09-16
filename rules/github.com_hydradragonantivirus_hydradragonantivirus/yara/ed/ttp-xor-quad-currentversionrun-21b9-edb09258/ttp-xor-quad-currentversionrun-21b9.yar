rule TTP_XOR_QUAD_CurrentVersionRun_21b9 {
  strings:
    $key_21b9 = { 72 d6 [2] 56 d8 [2] 7d f4 [2] 53 d6 [2] 47 cd [2] 48 d7 [2] 56 ca [2] 54 cb [2] 4f cd [2] 53 ca [2] 4f e5 }

  condition:
    any of them
}