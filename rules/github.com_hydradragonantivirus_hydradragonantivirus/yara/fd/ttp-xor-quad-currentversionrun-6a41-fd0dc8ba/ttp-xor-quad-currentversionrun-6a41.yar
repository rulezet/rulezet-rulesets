rule TTP_XOR_QUAD_CurrentVersionRun_6a41 {
  strings:
    $key_6a41 = { 39 2e [2] 1d 20 [2] 36 0c [2] 18 2e [2] 0c 35 [2] 03 2f [2] 1d 32 [2] 1f 33 [2] 04 35 [2] 18 32 [2] 04 1d }

  condition:
    any of them
}