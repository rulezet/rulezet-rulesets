rule TTP_XOR_QUAD_CurrentVersionRun_2533 {
  strings:
    $key_2533 = { 76 5c [2] 52 52 [2] 79 7e [2] 57 5c [2] 43 47 [2] 4c 5d [2] 52 40 [2] 50 41 [2] 4b 47 [2] 57 40 [2] 4b 6f }

  condition:
    any of them
}