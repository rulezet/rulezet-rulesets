rule TTP_XOR_QUAD_CurrentVersionRun_2603 {
  strings:
    $key_2603 = { 75 6c [2] 51 62 [2] 7a 4e [2] 54 6c [2] 40 77 [2] 4f 6d [2] 51 70 [2] 53 71 [2] 48 77 [2] 54 70 [2] 48 5f }

  condition:
    any of them
}