rule TTP_XOR_QUAD_CurrentVersionRun_ffae {
  strings:
    $key_ffae = { ac c1 [2] 88 cf [2] a3 e3 [2] 8d c1 [2] 99 da [2] 96 c0 [2] 88 dd [2] 8a dc [2] 91 da [2] 8d dd [2] 91 f2 }

  condition:
    any of them
}