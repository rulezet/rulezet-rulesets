rule TTP_XOR_QUAD_CurrentVersionRun_e098 {
  strings:
    $key_e098 = { b3 f7 [2] 97 f9 [2] bc d5 [2] 92 f7 [2] 86 ec [2] 89 f6 [2] 97 eb [2] 95 ea [2] 8e ec [2] 92 eb [2] 8e c4 }

  condition:
    any of them
}