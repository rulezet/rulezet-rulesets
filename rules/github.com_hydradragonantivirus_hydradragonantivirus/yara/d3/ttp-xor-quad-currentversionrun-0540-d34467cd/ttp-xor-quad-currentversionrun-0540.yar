rule TTP_XOR_QUAD_CurrentVersionRun_0540 {
  strings:
    $key_0540 = { 56 2f [2] 72 21 [2] 59 0d [2] 77 2f [2] 63 34 [2] 6c 2e [2] 72 33 [2] 70 32 [2] 6b 34 [2] 77 33 [2] 6b 1c }

  condition:
    any of them
}