rule TTP_XOR_QUAD_CurrentVersionRun_d282 {
  strings:
    $key_d282 = { 81 ed [2] a5 e3 [2] 8e cf [2] a0 ed [2] b4 f6 [2] bb ec [2] a5 f1 [2] a7 f0 [2] bc f6 [2] a0 f1 [2] bc de }

  condition:
    any of them
}