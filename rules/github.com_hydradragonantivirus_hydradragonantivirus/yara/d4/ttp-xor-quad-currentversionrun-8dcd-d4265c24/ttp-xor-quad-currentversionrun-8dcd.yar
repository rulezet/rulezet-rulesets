rule TTP_XOR_QUAD_CurrentVersionRun_8dcd {
  strings:
    $key_8dcd = { de a2 [2] fa ac [2] d1 80 [2] ff a2 [2] eb b9 [2] e4 a3 [2] fa be [2] f8 bf [2] e3 b9 [2] ff be [2] e3 91 }

  condition:
    any of them
}