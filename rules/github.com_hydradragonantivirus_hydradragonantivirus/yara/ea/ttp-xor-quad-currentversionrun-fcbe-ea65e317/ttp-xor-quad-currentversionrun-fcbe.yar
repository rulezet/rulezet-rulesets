rule TTP_XOR_QUAD_CurrentVersionRun_fcbe {
  strings:
    $key_fcbe = { af d1 [2] 8b df [2] a0 f3 [2] 8e d1 [2] 9a ca [2] 95 d0 [2] 8b cd [2] 89 cc [2] 92 ca [2] 8e cd [2] 92 e2 }

  condition:
    any of them
}