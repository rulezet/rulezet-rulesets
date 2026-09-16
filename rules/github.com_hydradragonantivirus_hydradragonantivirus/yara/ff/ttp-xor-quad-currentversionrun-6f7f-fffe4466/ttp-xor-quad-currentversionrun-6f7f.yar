rule TTP_XOR_QUAD_CurrentVersionRun_6f7f {
  strings:
    $key_6f7f = { 3c 10 [2] 18 1e [2] 33 32 [2] 1d 10 [2] 09 0b [2] 06 11 [2] 18 0c [2] 1a 0d [2] 01 0b [2] 1d 0c [2] 01 23 }

  condition:
    any of them
}