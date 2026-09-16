rule TTP_XOR_QUAD_CurrentVersionRun_1b9f {
  strings:
    $key_1b9f = { 48 f0 [2] 6c fe [2] 47 d2 [2] 69 f0 [2] 7d eb [2] 72 f1 [2] 6c ec [2] 6e ed [2] 75 eb [2] 69 ec [2] 75 c3 }

  condition:
    any of them
}