rule TTP_XOR_QUAD_CurrentVersionRun_d399 {
  strings:
    $key_d399 = { 80 f6 [2] a4 f8 [2] 8f d4 [2] a1 f6 [2] b5 ed [2] ba f7 [2] a4 ea [2] a6 eb [2] bd ed [2] a1 ea [2] bd c5 }

  condition:
    any of them
}