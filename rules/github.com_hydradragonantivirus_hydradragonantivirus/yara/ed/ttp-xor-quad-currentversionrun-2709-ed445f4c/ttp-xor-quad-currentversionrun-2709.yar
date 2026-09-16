rule TTP_XOR_QUAD_CurrentVersionRun_2709 {
  strings:
    $key_2709 = { 74 66 [2] 50 68 [2] 7b 44 [2] 55 66 [2] 41 7d [2] 4e 67 [2] 50 7a [2] 52 7b [2] 49 7d [2] 55 7a [2] 49 55 }

  condition:
    any of them
}