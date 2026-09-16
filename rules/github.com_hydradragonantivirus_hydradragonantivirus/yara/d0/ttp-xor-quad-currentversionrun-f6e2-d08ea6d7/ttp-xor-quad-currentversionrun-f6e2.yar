rule TTP_XOR_QUAD_CurrentVersionRun_f6e2 {
  strings:
    $key_f6e2 = { a5 8d [2] 81 83 [2] aa af [2] 84 8d [2] 90 96 [2] 9f 8c [2] 81 91 [2] 83 90 [2] 98 96 [2] 84 91 [2] 98 be }

  condition:
    any of them
}