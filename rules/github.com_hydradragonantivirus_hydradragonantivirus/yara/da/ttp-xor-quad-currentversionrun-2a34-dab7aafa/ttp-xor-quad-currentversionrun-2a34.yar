rule TTP_XOR_QUAD_CurrentVersionRun_2a34 {
  strings:
    $key_2a34 = { 79 5b [2] 5d 55 [2] 76 79 [2] 58 5b [2] 4c 40 [2] 43 5a [2] 5d 47 [2] 5f 46 [2] 44 40 [2] 58 47 [2] 44 68 }

  condition:
    any of them
}