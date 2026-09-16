rule TTP_XOR_QUAD_CurrentVersionRun_d798 {
  strings:
    $key_d798 = { 84 f7 [2] a0 f9 [2] 8b d5 [2] a5 f7 [2] b1 ec [2] be f6 [2] a0 eb [2] a2 ea [2] b9 ec [2] a5 eb [2] b9 c4 }

  condition:
    any of them
}