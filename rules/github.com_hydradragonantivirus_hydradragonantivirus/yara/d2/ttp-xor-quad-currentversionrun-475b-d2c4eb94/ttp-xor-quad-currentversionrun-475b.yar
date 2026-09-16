rule TTP_XOR_QUAD_CurrentVersionRun_475b {
  strings:
    $key_475b = { 14 34 [2] 30 3a [2] 1b 16 [2] 35 34 [2] 21 2f [2] 2e 35 [2] 30 28 [2] 32 29 [2] 29 2f [2] 35 28 [2] 29 07 }

  condition:
    any of them
}