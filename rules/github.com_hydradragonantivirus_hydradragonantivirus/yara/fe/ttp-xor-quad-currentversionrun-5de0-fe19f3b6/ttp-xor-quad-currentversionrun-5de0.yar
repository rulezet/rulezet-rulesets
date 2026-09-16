rule TTP_XOR_QUAD_CurrentVersionRun_5de0 {
  strings:
    $key_5de0 = { 0e 8f [2] 2a 81 [2] 01 ad [2] 2f 8f [2] 3b 94 [2] 34 8e [2] 2a 93 [2] 28 92 [2] 33 94 [2] 2f 93 [2] 33 bc }

  condition:
    any of them
}