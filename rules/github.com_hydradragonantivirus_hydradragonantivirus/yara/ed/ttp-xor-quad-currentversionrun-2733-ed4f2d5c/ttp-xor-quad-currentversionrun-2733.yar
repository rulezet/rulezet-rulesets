rule TTP_XOR_QUAD_CurrentVersionRun_2733 {
  strings:
    $key_2733 = { 74 5c [2] 50 52 [2] 7b 7e [2] 55 5c [2] 41 47 [2] 4e 5d [2] 50 40 [2] 52 41 [2] 49 47 [2] 55 40 [2] 49 6f }

  condition:
    any of them
}