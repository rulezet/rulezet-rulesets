rule TTP_XOR_QUAD_CurrentVersionRun_51e2 {
  strings:
    $key_51e2 = { 02 8d [2] 26 83 [2] 0d af [2] 23 8d [2] 37 96 [2] 38 8c [2] 26 91 [2] 24 90 [2] 3f 96 [2] 23 91 [2] 3f be }

  condition:
    any of them
}