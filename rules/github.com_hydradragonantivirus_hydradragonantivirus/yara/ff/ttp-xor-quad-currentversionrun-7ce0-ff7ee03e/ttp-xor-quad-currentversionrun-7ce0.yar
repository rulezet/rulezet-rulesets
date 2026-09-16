rule TTP_XOR_QUAD_CurrentVersionRun_7ce0 {
  strings:
    $key_7ce0 = { 2f 8f [2] 0b 81 [2] 20 ad [2] 0e 8f [2] 1a 94 [2] 15 8e [2] 0b 93 [2] 09 92 [2] 12 94 [2] 0e 93 [2] 12 bc }

  condition:
    any of them
}