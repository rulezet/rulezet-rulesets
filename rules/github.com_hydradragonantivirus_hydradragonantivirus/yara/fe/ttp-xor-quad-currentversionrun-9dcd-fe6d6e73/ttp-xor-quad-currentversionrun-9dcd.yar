rule TTP_XOR_QUAD_CurrentVersionRun_9dcd {
  strings:
    $key_9dcd = { ce a2 [2] ea ac [2] c1 80 [2] ef a2 [2] fb b9 [2] f4 a3 [2] ea be [2] e8 bf [2] f3 b9 [2] ef be [2] f3 91 }

  condition:
    any of them
}