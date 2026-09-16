rule TTP_XOR_QUAD_CurrentVersionRun_699e {
  strings:
    $key_699e = { 3a f1 [2] 1e ff [2] 35 d3 [2] 1b f1 [2] 0f ea [2] 00 f0 [2] 1e ed [2] 1c ec [2] 07 ea [2] 1b ed [2] 07 c2 }

  condition:
    any of them
}