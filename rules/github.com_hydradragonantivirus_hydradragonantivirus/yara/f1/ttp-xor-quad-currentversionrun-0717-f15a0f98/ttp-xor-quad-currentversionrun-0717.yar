rule TTP_XOR_QUAD_CurrentVersionRun_0717 {
  strings:
    $key_0717 = { 54 78 [2] 70 76 [2] 5b 5a [2] 75 78 [2] 61 63 [2] 6e 79 [2] 70 64 [2] 72 65 [2] 69 63 [2] 75 64 [2] 69 4b }

  condition:
    any of them
}