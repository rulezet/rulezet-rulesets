rule TTP_XOR_QUAD_CurrentVersionRun_00cc {
  strings:
    $key_00cc = { 53 a3 [2] 77 ad [2] 5c 81 [2] 72 a3 [2] 66 b8 [2] 69 a2 [2] 77 bf [2] 75 be [2] 6e b8 [2] 72 bf [2] 6e 90 }

  condition:
    any of them
}