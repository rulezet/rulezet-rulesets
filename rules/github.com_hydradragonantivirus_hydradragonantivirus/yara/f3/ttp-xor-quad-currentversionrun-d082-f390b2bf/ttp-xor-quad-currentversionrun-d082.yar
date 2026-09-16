rule TTP_XOR_QUAD_CurrentVersionRun_d082 {
  strings:
    $key_d082 = { 83 ed [2] a7 e3 [2] 8c cf [2] a2 ed [2] b6 f6 [2] b9 ec [2] a7 f1 [2] a5 f0 [2] be f6 [2] a2 f1 [2] be de }

  condition:
    any of them
}