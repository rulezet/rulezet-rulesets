rule TTP_XOR_QUAD_CurrentVersionRun_e7e2 {
  strings:
    $key_e7e2 = { b4 8d [2] 90 83 [2] bb af [2] 95 8d [2] 81 96 [2] 8e 8c [2] 90 91 [2] 92 90 [2] 89 96 [2] 95 91 [2] 89 be }

  condition:
    any of them
}