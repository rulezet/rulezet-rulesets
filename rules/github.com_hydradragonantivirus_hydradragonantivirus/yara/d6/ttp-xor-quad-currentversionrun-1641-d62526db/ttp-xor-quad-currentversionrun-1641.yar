rule TTP_XOR_QUAD_CurrentVersionRun_1641 {
  strings:
    $key_1641 = { 45 2e [2] 61 20 [2] 4a 0c [2] 64 2e [2] 70 35 [2] 7f 2f [2] 61 32 [2] 63 33 [2] 78 35 [2] 64 32 [2] 78 1d }

  condition:
    any of them
}