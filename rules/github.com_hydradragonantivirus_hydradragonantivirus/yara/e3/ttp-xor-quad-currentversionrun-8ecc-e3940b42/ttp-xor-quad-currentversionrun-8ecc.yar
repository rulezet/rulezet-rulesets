rule TTP_XOR_QUAD_CurrentVersionRun_8ecc {
  strings:
    $key_8ecc = { dd a3 [2] f9 ad [2] d2 81 [2] fc a3 [2] e8 b8 [2] e7 a2 [2] f9 bf [2] fb be [2] e0 b8 [2] fc bf [2] e0 90 }

  condition:
    any of them
}