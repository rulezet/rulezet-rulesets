rule TTP_XOR_QUAD_CurrentVersionRun_2f08 {
  strings:
    $key_2f08 = { 7c 67 [2] 58 69 [2] 73 45 [2] 5d 67 [2] 49 7c [2] 46 66 [2] 58 7b [2] 5a 7a [2] 41 7c [2] 5d 7b [2] 41 54 }

  condition:
    any of them
}