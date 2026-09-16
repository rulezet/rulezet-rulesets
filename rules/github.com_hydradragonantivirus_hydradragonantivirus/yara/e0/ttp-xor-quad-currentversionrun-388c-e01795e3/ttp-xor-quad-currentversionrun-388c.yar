rule TTP_XOR_QUAD_CurrentVersionRun_388c {
  strings:
    $key_388c = { 6b e3 [2] 4f ed [2] 64 c1 [2] 4a e3 [2] 5e f8 [2] 51 e2 [2] 4f ff [2] 4d fe [2] 56 f8 [2] 4a ff [2] 56 d0 }

  condition:
    any of them
}