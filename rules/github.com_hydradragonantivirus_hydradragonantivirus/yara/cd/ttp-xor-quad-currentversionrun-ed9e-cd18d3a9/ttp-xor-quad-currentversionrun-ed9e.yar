rule TTP_XOR_QUAD_CurrentVersionRun_ed9e {
  strings:
    $key_ed9e = { be f1 [2] 9a ff [2] b1 d3 [2] 9f f1 [2] 8b ea [2] 84 f0 [2] 9a ed [2] 98 ec [2] 83 ea [2] 9f ed [2] 83 c2 }

  condition:
    any of them
}