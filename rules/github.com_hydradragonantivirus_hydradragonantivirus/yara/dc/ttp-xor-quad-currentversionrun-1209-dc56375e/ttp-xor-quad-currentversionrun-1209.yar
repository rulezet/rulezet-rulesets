rule TTP_XOR_QUAD_CurrentVersionRun_1209 {
  strings:
    $key_1209 = { 41 66 [2] 65 68 [2] 4e 44 [2] 60 66 [2] 74 7d [2] 7b 67 [2] 65 7a [2] 67 7b [2] 7c 7d [2] 60 7a [2] 7c 55 }

  condition:
    any of them
}