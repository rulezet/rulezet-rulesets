rule TTP_XOR_QUAD_CurrentVersionRun_2641 {
  strings:
    $key_2641 = { 75 2e [2] 51 20 [2] 7a 0c [2] 54 2e [2] 40 35 [2] 4f 2f [2] 51 32 [2] 53 33 [2] 48 35 [2] 54 32 [2] 48 1d }

  condition:
    any of them
}