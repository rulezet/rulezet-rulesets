rule TTP_XOR_QUAD_CurrentVersionRun_4641 {
  strings:
    $key_4641 = { 15 2e [2] 31 20 [2] 1a 0c [2] 34 2e [2] 20 35 [2] 2f 2f [2] 31 32 [2] 33 33 [2] 28 35 [2] 34 32 [2] 28 1d }

  condition:
    any of them
}