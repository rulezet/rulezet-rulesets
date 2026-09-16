rule TTP_XOR_QUAD_CurrentVersionRun_207c {
  strings:
    $key_207c = { 73 13 [2] 57 1d [2] 7c 31 [2] 52 13 [2] 46 08 [2] 49 12 [2] 57 0f [2] 55 0e [2] 4e 08 [2] 52 0f [2] 4e 20 }

  condition:
    any of them
}