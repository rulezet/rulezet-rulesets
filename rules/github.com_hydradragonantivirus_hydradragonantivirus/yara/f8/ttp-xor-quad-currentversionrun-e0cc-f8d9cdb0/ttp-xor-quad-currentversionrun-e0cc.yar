rule TTP_XOR_QUAD_CurrentVersionRun_e0cc {
  strings:
    $key_e0cc = { b3 a3 [2] 97 ad [2] bc 81 [2] 92 a3 [2] 86 b8 [2] 89 a2 [2] 97 bf [2] 95 be [2] 8e b8 [2] 92 bf [2] 8e 90 }

  condition:
    any of them
}