rule TTP_XOR_QUAD_CurrentVersionRun_1135 {
  strings:
    $key_1135 = { 42 5a [2] 66 54 [2] 4d 78 [2] 63 5a [2] 77 41 [2] 78 5b [2] 66 46 [2] 64 47 [2] 7f 41 [2] 63 46 [2] 7f 69 }

  condition:
    any of them
}