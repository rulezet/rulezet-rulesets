rule TTP_XOR_QUAD_CurrentVersionRun_ccbc {
  strings:
    $key_ccbc = { 9f d3 [2] bb dd [2] 90 f1 [2] be d3 [2] aa c8 [2] a5 d2 [2] bb cf [2] b9 ce [2] a2 c8 [2] be cf [2] a2 e0 }

  condition:
    any of them
}