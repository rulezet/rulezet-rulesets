rule TTP_XOR_QUAD_CurrentVersionRun_0919 {
  strings:
    $key_0919 = { 5a 76 [2] 7e 78 [2] 55 54 [2] 7b 76 [2] 6f 6d [2] 60 77 [2] 7e 6a [2] 7c 6b [2] 67 6d [2] 7b 6a [2] 67 45 }

  condition:
    any of them
}