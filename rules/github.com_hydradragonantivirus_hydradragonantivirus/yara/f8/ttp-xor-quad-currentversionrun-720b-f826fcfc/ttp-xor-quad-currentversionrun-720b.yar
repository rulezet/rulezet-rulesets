rule TTP_XOR_QUAD_CurrentVersionRun_720b {
  strings:
    $key_720b = { 21 64 [2] 05 6a [2] 2e 46 [2] 00 64 [2] 14 7f [2] 1b 65 [2] 05 78 [2] 07 79 [2] 1c 7f [2] 00 78 [2] 1c 57 }

  condition:
    any of them
}