rule TTP_XOR_QUAD_CurrentVersionRun_516c {
  strings:
    $key_516c = { 02 03 [2] 26 0d [2] 0d 21 [2] 23 03 [2] 37 18 [2] 38 02 [2] 26 1f [2] 24 1e [2] 3f 18 [2] 23 1f [2] 3f 30 }

  condition:
    any of them
}