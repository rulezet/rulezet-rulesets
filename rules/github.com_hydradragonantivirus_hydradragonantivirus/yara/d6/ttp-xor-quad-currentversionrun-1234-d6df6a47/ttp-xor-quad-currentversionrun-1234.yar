rule TTP_XOR_QUAD_CurrentVersionRun_1234 {
  strings:
    $key_1234 = { 41 5b [2] 65 55 [2] 4e 79 [2] 60 5b [2] 74 40 [2] 7b 5a [2] 65 47 [2] 67 46 [2] 7c 40 [2] 60 47 [2] 7c 68 }

  condition:
    any of them
}