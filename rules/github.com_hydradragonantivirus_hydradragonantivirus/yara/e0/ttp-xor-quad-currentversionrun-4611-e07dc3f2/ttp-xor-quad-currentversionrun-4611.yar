rule TTP_XOR_QUAD_CurrentVersionRun_4611 {
  strings:
    $key_4611 = { 15 7e [2] 31 70 [2] 1a 5c [2] 34 7e [2] 20 65 [2] 2f 7f [2] 31 62 [2] 33 63 [2] 28 65 [2] 34 62 [2] 28 4d }

  condition:
    any of them
}