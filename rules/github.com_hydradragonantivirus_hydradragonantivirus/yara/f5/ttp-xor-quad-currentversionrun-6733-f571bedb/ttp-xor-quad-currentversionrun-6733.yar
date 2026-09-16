rule TTP_XOR_QUAD_CurrentVersionRun_6733 {
  strings:
    $key_6733 = { 34 5c [2] 10 52 [2] 3b 7e [2] 15 5c [2] 01 47 [2] 0e 5d [2] 10 40 [2] 12 41 [2] 09 47 [2] 15 40 [2] 09 6f }

  condition:
    any of them
}