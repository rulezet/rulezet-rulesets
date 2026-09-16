rule TTP_XOR_QUAD_CurrentVersionRun_f8ae {
  strings:
    $key_f8ae = { ab c1 [2] 8f cf [2] a4 e3 [2] 8a c1 [2] 9e da [2] 91 c0 [2] 8f dd [2] 8d dc [2] 96 da [2] 8a dd [2] 96 f2 }

  condition:
    any of them
}