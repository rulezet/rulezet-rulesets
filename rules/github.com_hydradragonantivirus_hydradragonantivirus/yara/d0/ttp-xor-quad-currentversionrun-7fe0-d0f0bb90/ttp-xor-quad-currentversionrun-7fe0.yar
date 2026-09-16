rule TTP_XOR_QUAD_CurrentVersionRun_7fe0 {
  strings:
    $key_7fe0 = { 2c 8f [2] 08 81 [2] 23 ad [2] 0d 8f [2] 19 94 [2] 16 8e [2] 08 93 [2] 0a 92 [2] 11 94 [2] 0d 93 [2] 11 bc }

  condition:
    any of them
}