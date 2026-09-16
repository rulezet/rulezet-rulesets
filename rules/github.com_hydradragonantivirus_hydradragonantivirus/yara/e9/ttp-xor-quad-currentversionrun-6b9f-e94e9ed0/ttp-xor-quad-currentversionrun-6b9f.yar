rule TTP_XOR_QUAD_CurrentVersionRun_6b9f {
  strings:
    $key_6b9f = { 38 f0 [2] 1c fe [2] 37 d2 [2] 19 f0 [2] 0d eb [2] 02 f1 [2] 1c ec [2] 1e ed [2] 05 eb [2] 19 ec [2] 05 c3 }

  condition:
    any of them
}