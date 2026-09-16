rule TTP_XOR_QUAD_CurrentVersionRun_4019 {
  strings:
    $key_4019 = { 13 76 [2] 37 78 [2] 1c 54 [2] 32 76 [2] 26 6d [2] 29 77 [2] 37 6a [2] 35 6b [2] 2e 6d [2] 32 6a [2] 2e 45 }

  condition:
    any of them
}