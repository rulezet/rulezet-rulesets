rule TTP_XOR_QUAD_CurrentVersionRun_6821 {
  strings:
    $key_6821 = { 3b 4e [2] 1f 40 [2] 34 6c [2] 1a 4e [2] 0e 55 [2] 01 4f [2] 1f 52 [2] 1d 53 [2] 06 55 [2] 1a 52 [2] 06 7d }

  condition:
    any of them
}