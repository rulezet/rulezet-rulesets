rule TTP_XOR_QUAD_CurrentVersionRun_dfd2 {
  strings:
    $key_dfd2 = { 8c bd [2] a8 b3 [2] 83 9f [2] ad bd [2] b9 a6 [2] b6 bc [2] a8 a1 [2] aa a0 [2] b1 a6 [2] ad a1 [2] b1 8e }

  condition:
    any of them
}