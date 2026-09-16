rule TTP_XOR_QUAD_CurrentVersionRun_c382 {
  strings:
    $key_c382 = { 90 ed [2] b4 e3 [2] 9f cf [2] b1 ed [2] a5 f6 [2] aa ec [2] b4 f1 [2] b6 f0 [2] ad f6 [2] b1 f1 [2] ad de }

  condition:
    any of them
}