rule TTP_XOR_QUAD_CurrentVersionRun_72cc {
  strings:
    $key_72cc = { 21 a3 [2] 05 ad [2] 2e 81 [2] 00 a3 [2] 14 b8 [2] 1b a2 [2] 05 bf [2] 07 be [2] 1c b8 [2] 00 bf [2] 1c 90 }

  condition:
    any of them
}