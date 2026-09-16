rule TTP_XOR_QUAD_CurrentVersionRun_6298 {
  strings:
    $key_6298 = { 31 f7 [2] 15 f9 [2] 3e d5 [2] 10 f7 [2] 04 ec [2] 0b f6 [2] 15 eb [2] 17 ea [2] 0c ec [2] 10 eb [2] 0c c4 }

  condition:
    any of them
}