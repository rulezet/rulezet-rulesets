rule TTP_XOR_QUAD_CurrentVersionRun_6be2 {
  strings:
    $key_6be2 = { 38 8d [2] 1c 83 [2] 37 af [2] 19 8d [2] 0d 96 [2] 02 8c [2] 1c 91 [2] 1e 90 [2] 05 96 [2] 19 91 [2] 05 be }

  condition:
    any of them
}