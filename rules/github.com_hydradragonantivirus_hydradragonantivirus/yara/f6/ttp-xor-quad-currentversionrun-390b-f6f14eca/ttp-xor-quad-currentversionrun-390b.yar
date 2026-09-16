rule TTP_XOR_QUAD_CurrentVersionRun_390b {
  strings:
    $key_390b = { 6a 64 [2] 4e 6a [2] 65 46 [2] 4b 64 [2] 5f 7f [2] 50 65 [2] 4e 78 [2] 4c 79 [2] 57 7f [2] 4b 78 [2] 57 57 }

  condition:
    any of them
}