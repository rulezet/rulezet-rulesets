rule TTP_XOR_QUAD_CurrentVersionRun_1e08 {
  strings:
    $key_1e08 = { 4d 67 [2] 69 69 [2] 42 45 [2] 6c 67 [2] 78 7c [2] 77 66 [2] 69 7b [2] 6b 7a [2] 70 7c [2] 6c 7b [2] 70 54 }

  condition:
    any of them
}