rule TTP_XOR_QUAD_CurrentVersionRun_ddbb {
  strings:
    $key_ddbb = { 8e d4 [2] aa da [2] 81 f6 [2] af d4 [2] bb cf [2] b4 d5 [2] aa c8 [2] a8 c9 [2] b3 cf [2] af c8 [2] b3 e7 }

  condition:
    any of them
}