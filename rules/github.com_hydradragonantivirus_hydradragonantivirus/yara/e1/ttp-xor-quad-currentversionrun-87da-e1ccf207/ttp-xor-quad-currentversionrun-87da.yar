rule TTP_XOR_QUAD_CurrentVersionRun_87da {
  strings:
    $key_87da = { d4 b5 [2] f0 bb [2] db 97 [2] f5 b5 [2] e1 ae [2] ee b4 [2] f0 a9 [2] f2 a8 [2] e9 ae [2] f5 a9 [2] e9 86 }

  condition:
    any of them
}