rule TTP_XOR_QUAD_CurrentVersionRun_c9cc {
  strings:
    $key_c9cc = { 9a a3 [2] be ad [2] 95 81 [2] bb a3 [2] af b8 [2] a0 a2 [2] be bf [2] bc be [2] a7 b8 [2] bb bf [2] a7 90 }

  condition:
    any of them
}