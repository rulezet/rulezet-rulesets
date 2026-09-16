rule TTP_XOR_QUAD_CurrentVersionRun_e924 {
  strings:
    $key_e924 = { ba 4b [2] 9e 45 [2] b5 69 [2] 9b 4b [2] 8f 50 [2] 80 4a [2] 9e 57 [2] 9c 56 [2] 87 50 [2] 9b 57 [2] 87 78 }

  condition:
    any of them
}