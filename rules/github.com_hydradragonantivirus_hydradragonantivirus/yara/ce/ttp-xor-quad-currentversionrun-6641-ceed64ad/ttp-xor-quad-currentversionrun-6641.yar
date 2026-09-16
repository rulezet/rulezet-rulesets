rule TTP_XOR_QUAD_CurrentVersionRun_6641 {
  strings:
    $key_6641 = { 35 2e [2] 11 20 [2] 3a 0c [2] 14 2e [2] 00 35 [2] 0f 2f [2] 11 32 [2] 13 33 [2] 08 35 [2] 14 32 [2] 08 1d }

  condition:
    any of them
}