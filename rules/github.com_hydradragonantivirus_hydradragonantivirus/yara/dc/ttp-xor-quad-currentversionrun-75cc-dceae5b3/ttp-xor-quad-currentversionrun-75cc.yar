rule TTP_XOR_QUAD_CurrentVersionRun_75cc {
  strings:
    $key_75cc = { 26 a3 [2] 02 ad [2] 29 81 [2] 07 a3 [2] 13 b8 [2] 1c a2 [2] 02 bf [2] 00 be [2] 1b b8 [2] 07 bf [2] 1b 90 }

  condition:
    any of them
}