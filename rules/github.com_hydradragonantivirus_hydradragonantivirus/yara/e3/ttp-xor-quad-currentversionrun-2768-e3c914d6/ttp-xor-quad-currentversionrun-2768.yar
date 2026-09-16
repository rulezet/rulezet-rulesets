rule TTP_XOR_QUAD_CurrentVersionRun_2768 {
  strings:
    $key_2768 = { 74 07 [2] 50 09 [2] 7b 25 [2] 55 07 [2] 41 1c [2] 4e 06 [2] 50 1b [2] 52 1a [2] 49 1c [2] 55 1b [2] 49 34 }

  condition:
    any of them
}