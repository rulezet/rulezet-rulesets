rule TTP_XOR_QUAD_CurrentVersionRun_f4e2 {
  strings:
    $key_f4e2 = { a7 8d [2] 83 83 [2] a8 af [2] 86 8d [2] 92 96 [2] 9d 8c [2] 83 91 [2] 81 90 [2] 9a 96 [2] 86 91 [2] 9a be }

  condition:
    any of them
}