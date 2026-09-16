rule TTP_XOR_QUAD_CurrentVersionRun_16a5 {
  strings:
    $key_16a5 = { 45 ca [2] 61 c4 [2] 4a e8 [2] 64 ca [2] 70 d1 [2] 7f cb [2] 61 d6 [2] 63 d7 [2] 78 d1 [2] 64 d6 [2] 78 f9 }

  condition:
    any of them
}