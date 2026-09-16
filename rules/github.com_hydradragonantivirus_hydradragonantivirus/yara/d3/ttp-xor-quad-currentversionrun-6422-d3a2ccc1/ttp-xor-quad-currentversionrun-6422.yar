rule TTP_XOR_QUAD_CurrentVersionRun_6422 {
  strings:
    $key_6422 = { 37 4d [2] 13 43 [2] 38 6f [2] 16 4d [2] 02 56 [2] 0d 4c [2] 13 51 [2] 11 50 [2] 0a 56 [2] 16 51 [2] 0a 7e }

  condition:
    any of them
}