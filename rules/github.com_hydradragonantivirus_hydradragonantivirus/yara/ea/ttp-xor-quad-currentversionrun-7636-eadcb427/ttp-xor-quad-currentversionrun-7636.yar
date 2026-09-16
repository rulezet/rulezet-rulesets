rule TTP_XOR_QUAD_CurrentVersionRun_7636 {
  strings:
    $key_7636 = { 25 59 [2] 01 57 [2] 2a 7b [2] 04 59 [2] 10 42 [2] 1f 58 [2] 01 45 [2] 03 44 [2] 18 42 [2] 04 45 [2] 18 6a }

  condition:
    any of them
}