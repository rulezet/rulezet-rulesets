rule TTP_XOR_QUAD_CurrentVersionRun_1717 {
  strings:
    $key_1717 = { 44 78 [2] 60 76 [2] 4b 5a [2] 65 78 [2] 71 63 [2] 7e 79 [2] 60 64 [2] 62 65 [2] 79 63 [2] 65 64 [2] 79 4b }

  condition:
    any of them
}