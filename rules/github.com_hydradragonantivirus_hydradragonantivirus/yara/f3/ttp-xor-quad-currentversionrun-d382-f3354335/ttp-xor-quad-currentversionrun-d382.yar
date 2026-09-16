rule TTP_XOR_QUAD_CurrentVersionRun_d382 {
  strings:
    $key_d382 = { 80 ed [2] a4 e3 [2] 8f cf [2] a1 ed [2] b5 f6 [2] ba ec [2] a4 f1 [2] a6 f0 [2] bd f6 [2] a1 f1 [2] bd de }

  condition:
    any of them
}