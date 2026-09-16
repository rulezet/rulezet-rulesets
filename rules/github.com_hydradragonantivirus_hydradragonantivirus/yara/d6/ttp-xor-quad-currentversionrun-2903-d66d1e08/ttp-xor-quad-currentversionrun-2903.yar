rule TTP_XOR_QUAD_CurrentVersionRun_2903 {
  strings:
    $key_2903 = { 7a 6c [2] 5e 62 [2] 75 4e [2] 5b 6c [2] 4f 77 [2] 40 6d [2] 5e 70 [2] 5c 71 [2] 47 77 [2] 5b 70 [2] 47 5f }

  condition:
    any of them
}