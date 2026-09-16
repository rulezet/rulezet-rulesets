rule TTP_XOR_QUAD_CurrentVersionRun_3ef9 {
  strings:
    $key_3ef9 = { 6d 96 [2] 49 98 [2] 62 b4 [2] 4c 96 [2] 58 8d [2] 57 97 [2] 49 8a [2] 4b 8b [2] 50 8d [2] 4c 8a [2] 50 a5 }

  condition:
    any of them
}