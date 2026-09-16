rule TTP_XOR_QUAD_CurrentVersionRun_713a {
  strings:
    $key_713a = { 22 55 [2] 06 5b [2] 2d 77 [2] 03 55 [2] 17 4e [2] 18 54 [2] 06 49 [2] 04 48 [2] 1f 4e [2] 03 49 [2] 1f 66 }

  condition:
    any of them
}