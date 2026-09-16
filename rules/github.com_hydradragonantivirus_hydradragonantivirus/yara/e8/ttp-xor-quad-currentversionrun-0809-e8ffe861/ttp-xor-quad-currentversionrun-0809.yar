rule TTP_XOR_QUAD_CurrentVersionRun_0809 {
  strings:
    $key_0809 = { 5b 66 [2] 7f 68 [2] 54 44 [2] 7a 66 [2] 6e 7d [2] 61 67 [2] 7f 7a [2] 7d 7b [2] 66 7d [2] 7a 7a [2] 66 55 }

  condition:
    any of them
}