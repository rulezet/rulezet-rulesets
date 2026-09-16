rule TTP_XOR_QUAD_CurrentVersionRun_5c3d {
  strings:
    $key_5c3d = { 0f 52 [2] 2b 5c [2] 00 70 [2] 2e 52 [2] 3a 49 [2] 35 53 [2] 2b 4e [2] 29 4f [2] 32 49 [2] 2e 4e [2] 32 61 }

  condition:
    any of them
}