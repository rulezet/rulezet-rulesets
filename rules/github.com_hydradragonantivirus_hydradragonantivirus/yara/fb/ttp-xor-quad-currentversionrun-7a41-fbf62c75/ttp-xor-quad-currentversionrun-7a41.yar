rule TTP_XOR_QUAD_CurrentVersionRun_7a41 {
  strings:
    $key_7a41 = { 29 2e [2] 0d 20 [2] 26 0c [2] 08 2e [2] 1c 35 [2] 13 2f [2] 0d 32 [2] 0f 33 [2] 14 35 [2] 08 32 [2] 14 1d }

  condition:
    any of them
}