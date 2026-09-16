rule TTP_XOR_QUAD_CurrentVersionRun_732f {
  strings:
    $key_732f = { 20 40 [2] 04 4e [2] 2f 62 [2] 01 40 [2] 15 5b [2] 1a 41 [2] 04 5c [2] 06 5d [2] 1d 5b [2] 01 5c [2] 1d 73 }

  condition:
    any of them
}