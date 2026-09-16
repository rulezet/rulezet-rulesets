rule TTP_XOR_QUAD_CurrentVersionRun_6cae {
  strings:
    $key_6cae = { 3f c1 [2] 1b cf [2] 30 e3 [2] 1e c1 [2] 0a da [2] 05 c0 [2] 1b dd [2] 19 dc [2] 02 da [2] 1e dd [2] 02 f2 }

  condition:
    any of them
}