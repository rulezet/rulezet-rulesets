rule TTP_XOR_QUAD_CurrentVersionRun_6224 {
  strings:
    $key_6224 = { 31 4b [2] 15 45 [2] 3e 69 [2] 10 4b [2] 04 50 [2] 0b 4a [2] 15 57 [2] 17 56 [2] 0c 50 [2] 10 57 [2] 0c 78 }

  condition:
    any of them
}