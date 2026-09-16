rule TTP_XOR_QUAD_CurrentVersionRun_388d {
  strings:
    $key_388d = { 6b e2 [2] 4f ec [2] 64 c0 [2] 4a e2 [2] 5e f9 [2] 51 e3 [2] 4f fe [2] 4d ff [2] 56 f9 [2] 4a fe [2] 56 d1 }

  condition:
    any of them
}