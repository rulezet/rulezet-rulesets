rule TTP_XOR_QUAD_CurrentVersionRun_1298 {
  strings:
    $key_1298 = { 41 f7 [2] 65 f9 [2] 4e d5 [2] 60 f7 [2] 74 ec [2] 7b f6 [2] 65 eb [2] 67 ea [2] 7c ec [2] 60 eb [2] 7c c4 }

  condition:
    any of them
}