rule TTP_XOR_QUAD_CurrentVersionRun_79f9 {
  strings:
    $key_79f9 = { 2a 96 [2] 0e 98 [2] 25 b4 [2] 0b 96 [2] 1f 8d [2] 10 97 [2] 0e 8a [2] 0c 8b [2] 17 8d [2] 0b 8a [2] 17 a5 }

  condition:
    any of them
}