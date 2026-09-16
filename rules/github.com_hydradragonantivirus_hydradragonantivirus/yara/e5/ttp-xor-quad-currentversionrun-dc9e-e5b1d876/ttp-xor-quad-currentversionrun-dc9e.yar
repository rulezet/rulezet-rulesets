rule TTP_XOR_QUAD_CurrentVersionRun_dc9e {
  strings:
    $key_dc9e = { 8f f1 [2] ab ff [2] 80 d3 [2] ae f1 [2] ba ea [2] b5 f0 [2] ab ed [2] a9 ec [2] b2 ea [2] ae ed [2] b2 c2 }

  condition:
    any of them
}