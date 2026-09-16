rule TTP_XOR_QUAD_CurrentVersionRun_7650 {
  strings:
    $key_7650 = { 25 3f [2] 01 31 [2] 2a 1d [2] 04 3f [2] 10 24 [2] 1f 3e [2] 01 23 [2] 03 22 [2] 18 24 [2] 04 23 [2] 18 0c }

  condition:
    any of them
}