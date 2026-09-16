rule TTP_XOR_QUAD_CurrentVersionRun_1ce0 {
  strings:
    $key_1ce0 = { 4f 8f [2] 6b 81 [2] 40 ad [2] 6e 8f [2] 7a 94 [2] 75 8e [2] 6b 93 [2] 69 92 [2] 72 94 [2] 6e 93 [2] 72 bc }

  condition:
    any of them
}