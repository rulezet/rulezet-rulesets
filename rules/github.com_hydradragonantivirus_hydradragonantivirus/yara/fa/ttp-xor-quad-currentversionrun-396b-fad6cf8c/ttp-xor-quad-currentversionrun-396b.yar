rule TTP_XOR_QUAD_CurrentVersionRun_396b {
  strings:
    $key_396b = { 6a 04 [2] 4e 0a [2] 65 26 [2] 4b 04 [2] 5f 1f [2] 50 05 [2] 4e 18 [2] 4c 19 [2] 57 1f [2] 4b 18 [2] 57 37 }

  condition:
    any of them
}