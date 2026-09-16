rule TTP_XOR_QUAD_CurrentVersionRun_5617 {
  strings:
    $key_5617 = { 05 78 [2] 21 76 [2] 0a 5a [2] 24 78 [2] 30 63 [2] 3f 79 [2] 21 64 [2] 23 65 [2] 38 63 [2] 24 64 [2] 38 4b }

  condition:
    any of them
}