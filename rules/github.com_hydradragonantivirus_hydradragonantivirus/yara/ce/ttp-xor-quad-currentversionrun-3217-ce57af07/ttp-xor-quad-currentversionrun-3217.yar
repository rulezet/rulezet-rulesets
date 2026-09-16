rule TTP_XOR_QUAD_CurrentVersionRun_3217 {
  strings:
    $key_3217 = { 61 78 [2] 45 76 [2] 6e 5a [2] 40 78 [2] 54 63 [2] 5b 79 [2] 45 64 [2] 47 65 [2] 5c 63 [2] 40 64 [2] 5c 4b }

  condition:
    any of them
}