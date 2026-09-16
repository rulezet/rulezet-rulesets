rule TTP_XOR_QUAD_CurrentVersionRun_691b {
  strings:
    $key_691b = { 3a 74 [2] 1e 7a [2] 35 56 [2] 1b 74 [2] 0f 6f [2] 00 75 [2] 1e 68 [2] 1c 69 [2] 07 6f [2] 1b 68 [2] 07 47 }

  condition:
    any of them
}