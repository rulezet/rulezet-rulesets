rule TTP_XOR_QUAD_CurrentVersionRun_7871 {
  strings:
    $key_7871 = { 2b 1e [2] 0f 10 [2] 24 3c [2] 0a 1e [2] 1e 05 [2] 11 1f [2] 0f 02 [2] 0d 03 [2] 16 05 [2] 0a 02 [2] 16 2d }

  condition:
    any of them
}