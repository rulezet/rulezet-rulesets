rule TTP_XOR_QUAD_CurrentVersionRun_3040 {
  strings:
    $key_3040 = { 63 2f [2] 47 21 [2] 6c 0d [2] 42 2f [2] 56 34 [2] 59 2e [2] 47 33 [2] 45 32 [2] 5e 34 [2] 42 33 [2] 5e 1c }

  condition:
    any of them
}