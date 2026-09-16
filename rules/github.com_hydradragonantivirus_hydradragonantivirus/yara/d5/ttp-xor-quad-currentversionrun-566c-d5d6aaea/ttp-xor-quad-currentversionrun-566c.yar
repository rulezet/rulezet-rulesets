rule TTP_XOR_QUAD_CurrentVersionRun_566c {
  strings:
    $key_566c = { 05 03 [2] 21 0d [2] 0a 21 [2] 24 03 [2] 30 18 [2] 3f 02 [2] 21 1f [2] 23 1e [2] 38 18 [2] 24 1f [2] 38 30 }

  condition:
    any of them
}