rule TTP_XOR_QUAD_CurrentVersionRun_7cae {
  strings:
    $key_7cae = { 2f c1 [2] 0b cf [2] 20 e3 [2] 0e c1 [2] 1a da [2] 15 c0 [2] 0b dd [2] 09 dc [2] 12 da [2] 0e dd [2] 12 f2 }

  condition:
    any of them
}