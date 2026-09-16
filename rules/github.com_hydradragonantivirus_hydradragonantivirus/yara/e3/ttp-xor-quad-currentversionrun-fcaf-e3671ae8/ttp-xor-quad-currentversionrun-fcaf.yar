rule TTP_XOR_QUAD_CurrentVersionRun_fcaf {
  strings:
    $key_fcaf = { af c0 [2] 8b ce [2] a0 e2 [2] 8e c0 [2] 9a db [2] 95 c1 [2] 8b dc [2] 89 dd [2] 92 db [2] 8e dc [2] 92 f3 }

  condition:
    any of them
}