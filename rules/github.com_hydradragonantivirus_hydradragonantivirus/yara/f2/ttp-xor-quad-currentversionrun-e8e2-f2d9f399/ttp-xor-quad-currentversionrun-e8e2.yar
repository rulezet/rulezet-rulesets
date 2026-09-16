rule TTP_XOR_QUAD_CurrentVersionRun_e8e2 {
  strings:
    $key_e8e2 = { bb 8d [2] 9f 83 [2] b4 af [2] 9a 8d [2] 8e 96 [2] 81 8c [2] 9f 91 [2] 9d 90 [2] 86 96 [2] 9a 91 [2] 86 be }

  condition:
    any of them
}