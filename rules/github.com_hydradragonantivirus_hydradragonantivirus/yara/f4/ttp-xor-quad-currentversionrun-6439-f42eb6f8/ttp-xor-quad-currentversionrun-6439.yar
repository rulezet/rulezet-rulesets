rule TTP_XOR_QUAD_CurrentVersionRun_6439 {
  strings:
    $key_6439 = { 37 56 [2] 13 58 [2] 38 74 [2] 16 56 [2] 02 4d [2] 0d 57 [2] 13 4a [2] 11 4b [2] 0a 4d [2] 16 4a [2] 0a 65 }

  condition:
    any of them
}