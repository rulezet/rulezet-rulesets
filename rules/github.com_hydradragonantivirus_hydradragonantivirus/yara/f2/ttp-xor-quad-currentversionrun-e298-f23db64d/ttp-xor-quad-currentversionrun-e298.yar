rule TTP_XOR_QUAD_CurrentVersionRun_e298 {
  strings:
    $key_e298 = { b1 f7 [2] 95 f9 [2] be d5 [2] 90 f7 [2] 84 ec [2] 8b f6 [2] 95 eb [2] 97 ea [2] 8c ec [2] 90 eb [2] 8c c4 }

  condition:
    any of them
}