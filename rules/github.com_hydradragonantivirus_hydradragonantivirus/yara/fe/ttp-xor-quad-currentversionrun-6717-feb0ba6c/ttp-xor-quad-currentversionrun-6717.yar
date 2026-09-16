rule TTP_XOR_QUAD_CurrentVersionRun_6717 {
  strings:
    $key_6717 = { 34 78 [2] 10 76 [2] 3b 5a [2] 15 78 [2] 01 63 [2] 0e 79 [2] 10 64 [2] 12 65 [2] 09 63 [2] 15 64 [2] 09 4b }

  condition:
    any of them
}