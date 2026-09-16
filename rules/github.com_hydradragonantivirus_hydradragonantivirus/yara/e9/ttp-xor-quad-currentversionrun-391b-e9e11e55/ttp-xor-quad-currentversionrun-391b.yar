rule TTP_XOR_QUAD_CurrentVersionRun_391b {
  strings:
    $key_391b = { 6a 74 [2] 4e 7a [2] 65 56 [2] 4b 74 [2] 5f 6f [2] 50 75 [2] 4e 68 [2] 4c 69 [2] 57 6f [2] 4b 68 [2] 57 47 }

  condition:
    any of them
}