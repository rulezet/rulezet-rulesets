rule TTP_XOR_QUAD_CurrentVersionRun_92d0 {
  strings:
    $key_92d0 = { c1 bf [2] e5 b1 [2] ce 9d [2] e0 bf [2] f4 a4 [2] fb be [2] e5 a3 [2] e7 a2 [2] fc a4 [2] e0 a3 [2] fc 8c }

  condition:
    any of them
}