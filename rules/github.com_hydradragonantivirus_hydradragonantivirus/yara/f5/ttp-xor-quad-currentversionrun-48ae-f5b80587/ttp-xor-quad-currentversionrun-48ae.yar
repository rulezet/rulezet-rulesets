rule TTP_XOR_QUAD_CurrentVersionRun_48ae {
  strings:
    $key_48ae = { 1b c1 [2] 3f cf [2] 14 e3 [2] 3a c1 [2] 2e da [2] 21 c0 [2] 3f dd [2] 3d dc [2] 26 da [2] 3a dd [2] 26 f2 }

  condition:
    any of them
}