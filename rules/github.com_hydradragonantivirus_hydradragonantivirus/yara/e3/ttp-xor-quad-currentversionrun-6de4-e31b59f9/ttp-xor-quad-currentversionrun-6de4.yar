rule TTP_XOR_QUAD_CurrentVersionRun_6de4 {
  strings:
    $key_6de4 = { 3e 8b [2] 1a 85 [2] 31 a9 [2] 1f 8b [2] 0b 90 [2] 04 8a [2] 1a 97 [2] 18 96 [2] 03 90 [2] 1f 97 [2] 03 b8 }

  condition:
    any of them
}