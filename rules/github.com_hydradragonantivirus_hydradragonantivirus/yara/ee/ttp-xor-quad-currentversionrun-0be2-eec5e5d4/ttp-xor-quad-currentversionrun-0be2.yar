rule TTP_XOR_QUAD_CurrentVersionRun_0be2 {
  strings:
    $key_0be2 = { 58 8d [2] 7c 83 [2] 57 af [2] 79 8d [2] 6d 96 [2] 62 8c [2] 7c 91 [2] 7e 90 [2] 65 96 [2] 79 91 [2] 65 be }

  condition:
    any of them
}