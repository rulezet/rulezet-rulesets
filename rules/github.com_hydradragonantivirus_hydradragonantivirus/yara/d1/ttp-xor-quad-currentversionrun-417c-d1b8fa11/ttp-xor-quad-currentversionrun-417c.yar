rule TTP_XOR_QUAD_CurrentVersionRun_417c {
  strings:
    $key_417c = { 12 13 [2] 36 1d [2] 1d 31 [2] 33 13 [2] 27 08 [2] 28 12 [2] 36 0f [2] 34 0e [2] 2f 08 [2] 33 0f [2] 2f 20 }

  condition:
    any of them
}