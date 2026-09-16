rule TTP_XOR_QUAD_CurrentVersionRun_312c {
  strings:
    $key_312c = { 62 43 [2] 46 4d [2] 6d 61 [2] 43 43 [2] 57 58 [2] 58 42 [2] 46 5f [2] 44 5e [2] 5f 58 [2] 43 5f [2] 5f 70 }

  condition:
    any of them
}