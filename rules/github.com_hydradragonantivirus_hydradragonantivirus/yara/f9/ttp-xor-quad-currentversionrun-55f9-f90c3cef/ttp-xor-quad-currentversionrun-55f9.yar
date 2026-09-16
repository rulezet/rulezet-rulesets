rule TTP_XOR_QUAD_CurrentVersionRun_55f9 {
  strings:
    $key_55f9 = { 06 96 [2] 22 98 [2] 09 b4 [2] 27 96 [2] 33 8d [2] 3c 97 [2] 22 8a [2] 20 8b [2] 3b 8d [2] 27 8a [2] 3b a5 }

  condition:
    any of them
}