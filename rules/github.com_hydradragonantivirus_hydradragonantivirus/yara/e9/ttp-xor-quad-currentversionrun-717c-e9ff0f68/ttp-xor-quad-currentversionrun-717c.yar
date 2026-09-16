rule TTP_XOR_QUAD_CurrentVersionRun_717c {
  strings:
    $key_717c = { 22 13 [2] 06 1d [2] 2d 31 [2] 03 13 [2] 17 08 [2] 18 12 [2] 06 0f [2] 04 0e [2] 1f 08 [2] 03 0f [2] 1f 20 }

  condition:
    any of them
}