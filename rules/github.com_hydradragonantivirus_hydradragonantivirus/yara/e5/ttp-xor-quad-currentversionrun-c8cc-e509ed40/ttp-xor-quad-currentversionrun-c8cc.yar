rule TTP_XOR_QUAD_CurrentVersionRun_c8cc {
  strings:
    $key_c8cc = { 9b a3 [2] bf ad [2] 94 81 [2] ba a3 [2] ae b8 [2] a1 a2 [2] bf bf [2] bd be [2] a6 b8 [2] ba bf [2] a6 90 }

  condition:
    any of them
}