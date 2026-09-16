rule TTP_XOR_QUAD_CurrentVersionRun_cfd1 {
  strings:
    $key_cfd1 = { 9c be [2] b8 b0 [2] 93 9c [2] bd be [2] a9 a5 [2] a6 bf [2] b8 a2 [2] ba a3 [2] a1 a5 [2] bd a2 [2] a1 8d }

  condition:
    any of them
}