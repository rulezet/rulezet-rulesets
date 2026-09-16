rule TTP_XOR_QUAD_CurrentVersionRun_0e34 {
  strings:
    $key_0e34 = { 5d 5b [2] 79 55 [2] 52 79 [2] 7c 5b [2] 68 40 [2] 67 5a [2] 79 47 [2] 7b 46 [2] 60 40 [2] 7c 47 [2] 60 68 }

  condition:
    any of them
}