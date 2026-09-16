rule TTP_XOR_QUAD_CurrentVersionRun_f88c {
  strings:
    $key_f88c = { ab e3 [2] 8f ed [2] a4 c1 [2] 8a e3 [2] 9e f8 [2] 91 e2 [2] 8f ff [2] 8d fe [2] 96 f8 [2] 8a ff [2] 96 d0 }

  condition:
    any of them
}