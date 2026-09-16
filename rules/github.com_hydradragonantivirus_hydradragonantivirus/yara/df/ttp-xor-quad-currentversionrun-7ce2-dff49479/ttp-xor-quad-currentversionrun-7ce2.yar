rule TTP_XOR_QUAD_CurrentVersionRun_7ce2 {
  strings:
    $key_7ce2 = { 2f 8d [2] 0b 83 [2] 20 af [2] 0e 8d [2] 1a 96 [2] 15 8c [2] 0b 91 [2] 09 90 [2] 12 96 [2] 0e 91 [2] 12 be }

  condition:
    any of them
}