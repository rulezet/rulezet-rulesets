rule TTP_XOR_QUAD_CurrentVersionRun_446d {
  strings:
    $key_446d = { 17 02 [2] 33 0c [2] 18 20 [2] 36 02 [2] 22 19 [2] 2d 03 [2] 33 1e [2] 31 1f [2] 2a 19 [2] 36 1e [2] 2a 31 }

  condition:
    any of them
}