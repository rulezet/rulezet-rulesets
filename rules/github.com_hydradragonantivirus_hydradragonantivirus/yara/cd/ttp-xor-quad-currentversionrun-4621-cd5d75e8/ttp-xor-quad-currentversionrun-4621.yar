rule TTP_XOR_QUAD_CurrentVersionRun_4621 {
  strings:
    $key_4621 = { 15 4e [2] 31 40 [2] 1a 6c [2] 34 4e [2] 20 55 [2] 2f 4f [2] 31 52 [2] 33 53 [2] 28 55 [2] 34 52 [2] 28 7d }

  condition:
    any of them
}