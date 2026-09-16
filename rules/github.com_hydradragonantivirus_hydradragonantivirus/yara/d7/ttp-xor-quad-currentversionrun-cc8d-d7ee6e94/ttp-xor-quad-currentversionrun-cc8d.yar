rule TTP_XOR_QUAD_CurrentVersionRun_cc8d {
  strings:
    $key_cc8d = { 9f e2 [2] bb ec [2] 90 c0 [2] be e2 [2] aa f9 [2] a5 e3 [2] bb fe [2] b9 ff [2] a2 f9 [2] be fe [2] a2 d1 }

  condition:
    any of them
}