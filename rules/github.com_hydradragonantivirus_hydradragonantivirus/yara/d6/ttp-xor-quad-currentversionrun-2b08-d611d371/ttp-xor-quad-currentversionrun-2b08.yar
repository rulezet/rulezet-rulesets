rule TTP_XOR_QUAD_CurrentVersionRun_2b08 {
  strings:
    $key_2b08 = { 78 67 [2] 5c 69 [2] 77 45 [2] 59 67 [2] 4d 7c [2] 42 66 [2] 5c 7b [2] 5e 7a [2] 45 7c [2] 59 7b [2] 45 54 }

  condition:
    any of them
}