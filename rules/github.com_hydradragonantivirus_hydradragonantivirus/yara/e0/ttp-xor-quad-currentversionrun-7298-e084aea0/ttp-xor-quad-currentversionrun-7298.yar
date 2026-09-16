rule TTP_XOR_QUAD_CurrentVersionRun_7298 {
  strings:
    $key_7298 = { 21 f7 [2] 05 f9 [2] 2e d5 [2] 00 f7 [2] 14 ec [2] 1b f6 [2] 05 eb [2] 07 ea [2] 1c ec [2] 00 eb [2] 1c c4 }

  condition:
    any of them
}