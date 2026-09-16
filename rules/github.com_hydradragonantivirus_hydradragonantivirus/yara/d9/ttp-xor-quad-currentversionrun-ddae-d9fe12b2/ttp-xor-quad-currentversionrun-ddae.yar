rule TTP_XOR_QUAD_CurrentVersionRun_ddae {
  strings:
    $key_ddae = { 8e c1 [2] aa cf [2] 81 e3 [2] af c1 [2] bb da [2] b4 c0 [2] aa dd [2] a8 dc [2] b3 da [2] af dd [2] b3 f2 }

  condition:
    any of them
}