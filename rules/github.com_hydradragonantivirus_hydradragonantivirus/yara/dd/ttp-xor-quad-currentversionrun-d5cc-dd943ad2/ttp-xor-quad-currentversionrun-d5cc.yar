rule TTP_XOR_QUAD_CurrentVersionRun_d5cc {
  strings:
    $key_d5cc = { 86 a3 [2] a2 ad [2] 89 81 [2] a7 a3 [2] b3 b8 [2] bc a2 [2] a2 bf [2] a0 be [2] bb b8 [2] a7 bf [2] bb 90 }

  condition:
    any of them
}