rule TTP_XOR_QUAD_CurrentVersionRun_3539 {
  strings:
    $key_3539 = { 66 56 [2] 42 58 [2] 69 74 [2] 47 56 [2] 53 4d [2] 5c 57 [2] 42 4a [2] 40 4b [2] 5b 4d [2] 47 4a [2] 5b 65 }

  condition:
    any of them
}