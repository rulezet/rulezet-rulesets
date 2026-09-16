rule TTP_XOR_QUAD_CurrentVersionRun_3536 {
  strings:
    $key_3536 = { 66 59 [2] 42 57 [2] 69 7b [2] 47 59 [2] 53 42 [2] 5c 58 [2] 42 45 [2] 40 44 [2] 5b 42 [2] 47 45 [2] 5b 6a }

  condition:
    any of them
}