rule TTP_XOR_QUAD_CurrentVersionRun_00e2 {
  strings:
    $key_00e2 = { 53 8d [2] 77 83 [2] 5c af [2] 72 8d [2] 66 96 [2] 69 8c [2] 77 91 [2] 75 90 [2] 6e 96 [2] 72 91 [2] 6e be }

  condition:
    any of them
}