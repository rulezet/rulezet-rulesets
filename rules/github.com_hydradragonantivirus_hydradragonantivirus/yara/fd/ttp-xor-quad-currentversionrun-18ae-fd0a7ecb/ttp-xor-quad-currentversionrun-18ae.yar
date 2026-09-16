rule TTP_XOR_QUAD_CurrentVersionRun_18ae {
  strings:
    $key_18ae = { 4b c1 [2] 6f cf [2] 44 e3 [2] 6a c1 [2] 7e da [2] 71 c0 [2] 6f dd [2] 6d dc [2] 76 da [2] 6a dd [2] 76 f2 }

  condition:
    any of them
}