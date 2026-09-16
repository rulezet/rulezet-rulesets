rule TTP_XOR_QUAD_CurrentVersionRun_6426 {
  strings:
    $key_6426 = { 37 49 [2] 13 47 [2] 38 6b [2] 16 49 [2] 02 52 [2] 0d 48 [2] 13 55 [2] 11 54 [2] 0a 52 [2] 16 55 [2] 0a 7a }

  condition:
    any of them
}