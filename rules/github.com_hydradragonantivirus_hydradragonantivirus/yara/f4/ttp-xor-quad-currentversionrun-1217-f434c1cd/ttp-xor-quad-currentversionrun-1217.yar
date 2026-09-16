rule TTP_XOR_QUAD_CurrentVersionRun_1217 {
  strings:
    $key_1217 = { 41 78 [2] 65 76 [2] 4e 5a [2] 60 78 [2] 74 63 [2] 7b 79 [2] 65 64 [2] 67 65 [2] 7c 63 [2] 60 64 [2] 7c 4b }

  condition:
    any of them
}