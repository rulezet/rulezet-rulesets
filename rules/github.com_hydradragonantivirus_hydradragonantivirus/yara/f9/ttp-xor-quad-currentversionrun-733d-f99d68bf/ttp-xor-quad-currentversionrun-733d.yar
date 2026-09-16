rule TTP_XOR_QUAD_CurrentVersionRun_733d {
  strings:
    $key_733d = { 20 52 [2] 04 5c [2] 2f 70 [2] 01 52 [2] 15 49 [2] 1a 53 [2] 04 4e [2] 06 4f [2] 1d 49 [2] 01 4e [2] 1d 61 }

  condition:
    any of them
}