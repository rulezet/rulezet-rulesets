rule TTP_XOR_QUAD_CurrentVersionRun_799e {
  strings:
    $key_799e = { 2a f1 [2] 0e ff [2] 25 d3 [2] 0b f1 [2] 1f ea [2] 10 f0 [2] 0e ed [2] 0c ec [2] 17 ea [2] 0b ed [2] 17 c2 }

  condition:
    any of them
}