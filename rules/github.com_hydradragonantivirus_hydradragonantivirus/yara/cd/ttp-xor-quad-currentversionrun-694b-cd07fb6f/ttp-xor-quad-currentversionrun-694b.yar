rule TTP_XOR_QUAD_CurrentVersionRun_694b {
  strings:
    $key_694b = { 3a 24 [2] 1e 2a [2] 35 06 [2] 1b 24 [2] 0f 3f [2] 00 25 [2] 1e 38 [2] 1c 39 [2] 07 3f [2] 1b 38 [2] 07 17 }

  condition:
    any of them
}