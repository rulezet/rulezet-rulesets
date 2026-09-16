rule TTP_XOR_QUAD_CurrentVersionRun_737c {
  strings:
    $key_737c = { 20 13 [2] 04 1d [2] 2f 31 [2] 01 13 [2] 15 08 [2] 1a 12 [2] 04 0f [2] 06 0e [2] 1d 08 [2] 01 0f [2] 1d 20 }

  condition:
    any of them
}