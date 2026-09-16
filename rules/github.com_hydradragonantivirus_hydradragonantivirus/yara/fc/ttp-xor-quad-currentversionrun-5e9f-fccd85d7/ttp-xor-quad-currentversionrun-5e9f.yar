rule TTP_XOR_QUAD_CurrentVersionRun_5e9f {
  strings:
    $key_5e9f = { 0d f0 [2] 29 fe [2] 02 d2 [2] 2c f0 [2] 38 eb [2] 37 f1 [2] 29 ec [2] 2b ed [2] 30 eb [2] 2c ec [2] 30 c3 }

  condition:
    any of them
}