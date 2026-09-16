rule TTP_XOR_QUAD_CurrentVersionRun_566a {
  strings:
    $key_566a = { 05 05 [2] 21 0b [2] 0a 27 [2] 24 05 [2] 30 1e [2] 3f 04 [2] 21 19 [2] 23 18 [2] 38 1e [2] 24 19 [2] 38 36 }

  condition:
    any of them
}