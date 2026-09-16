rule TTP_XOR_QUAD_CurrentVersionRun_1134 {
  strings:
    $key_1134 = { 42 5b [2] 66 55 [2] 4d 79 [2] 63 5b [2] 77 40 [2] 78 5a [2] 66 47 [2] 64 46 [2] 7f 40 [2] 63 47 [2] 7f 68 }

  condition:
    any of them
}