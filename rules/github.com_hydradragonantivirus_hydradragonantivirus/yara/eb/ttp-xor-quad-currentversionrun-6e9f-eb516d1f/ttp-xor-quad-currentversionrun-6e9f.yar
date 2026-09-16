rule TTP_XOR_QUAD_CurrentVersionRun_6e9f {
  strings:
    $key_6e9f = { 3d f0 [2] 19 fe [2] 32 d2 [2] 1c f0 [2] 08 eb [2] 07 f1 [2] 19 ec [2] 1b ed [2] 00 eb [2] 1c ec [2] 00 c3 }

  condition:
    any of them
}