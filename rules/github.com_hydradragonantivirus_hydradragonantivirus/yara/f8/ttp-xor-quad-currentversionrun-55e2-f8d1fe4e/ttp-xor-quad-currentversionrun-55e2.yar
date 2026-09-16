rule TTP_XOR_QUAD_CurrentVersionRun_55e2 {
  strings:
    $key_55e2 = { 06 8d [2] 22 83 [2] 09 af [2] 27 8d [2] 33 96 [2] 3c 8c [2] 22 91 [2] 20 90 [2] 3b 96 [2] 27 91 [2] 3b be }

  condition:
    any of them
}