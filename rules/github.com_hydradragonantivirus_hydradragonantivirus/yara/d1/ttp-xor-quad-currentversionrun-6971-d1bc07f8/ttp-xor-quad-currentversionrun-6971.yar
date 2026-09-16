rule TTP_XOR_QUAD_CurrentVersionRun_6971 {
  strings:
    $key_6971 = { 3a 1e [2] 1e 10 [2] 35 3c [2] 1b 1e [2] 0f 05 [2] 00 1f [2] 1e 02 [2] 1c 03 [2] 07 05 [2] 1b 02 [2] 07 2d }

  condition:
    any of them
}