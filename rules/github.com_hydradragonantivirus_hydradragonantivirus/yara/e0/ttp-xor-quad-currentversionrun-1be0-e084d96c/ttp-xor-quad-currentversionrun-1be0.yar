rule TTP_XOR_QUAD_CurrentVersionRun_1be0 {
  strings:
    $key_1be0 = { 48 8f [2] 6c 81 [2] 47 ad [2] 69 8f [2] 7d 94 [2] 72 8e [2] 6c 93 [2] 6e 92 [2] 75 94 [2] 69 93 [2] 75 bc }

  condition:
    any of them
}