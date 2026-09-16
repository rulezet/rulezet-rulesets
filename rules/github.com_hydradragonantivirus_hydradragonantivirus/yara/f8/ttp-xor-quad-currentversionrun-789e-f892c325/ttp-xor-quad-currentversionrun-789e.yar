rule TTP_XOR_QUAD_CurrentVersionRun_789e {
  strings:
    $key_789e = { 2b f1 [2] 0f ff [2] 24 d3 [2] 0a f1 [2] 1e ea [2] 11 f0 [2] 0f ed [2] 0d ec [2] 16 ea [2] 0a ed [2] 16 c2 }

  condition:
    any of them
}