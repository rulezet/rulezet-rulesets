rule TTP_XOR_QUAD_CurrentVersionRun_4b7f {
  strings:
    $key_4b7f = { 18 10 [2] 3c 1e [2] 17 32 [2] 39 10 [2] 2d 0b [2] 22 11 [2] 3c 0c [2] 3e 0d [2] 25 0b [2] 39 0c [2] 25 23 }

  condition:
    any of them
}