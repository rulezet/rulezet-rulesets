rule TTP_XOR_QUAD_CurrentVersionRun_0ce0 {
  strings:
    $key_0ce0 = { 5f 8f [2] 7b 81 [2] 50 ad [2] 7e 8f [2] 6a 94 [2] 65 8e [2] 7b 93 [2] 79 92 [2] 62 94 [2] 7e 93 [2] 62 bc }

  condition:
    any of them
}