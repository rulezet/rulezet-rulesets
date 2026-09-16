rule TTP_XOR_QUAD_CurrentVersionRun_28e0 {
  strings:
    $key_28e0 = { 7b 8f [2] 5f 81 [2] 74 ad [2] 5a 8f [2] 4e 94 [2] 41 8e [2] 5f 93 [2] 5d 92 [2] 46 94 [2] 5a 93 [2] 46 bc }

  condition:
    any of them
}