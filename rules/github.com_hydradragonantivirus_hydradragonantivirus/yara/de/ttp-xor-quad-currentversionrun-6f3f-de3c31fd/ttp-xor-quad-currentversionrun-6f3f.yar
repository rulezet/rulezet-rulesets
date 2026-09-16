rule TTP_XOR_QUAD_CurrentVersionRun_6f3f {
  strings:
    $key_6f3f = { 3c 50 [2] 18 5e [2] 33 72 [2] 1d 50 [2] 09 4b [2] 06 51 [2] 18 4c [2] 1a 4d [2] 01 4b [2] 1d 4c [2] 01 63 }

  condition:
    any of them
}