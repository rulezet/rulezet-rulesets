rule TTP_XOR_QUAD_CurrentVersionRun_2f7f {
  strings:
    $key_2f7f = { 7c 10 [2] 58 1e [2] 73 32 [2] 5d 10 [2] 49 0b [2] 46 11 [2] 58 0c [2] 5a 0d [2] 41 0b [2] 5d 0c [2] 41 23 }

  condition:
    any of them
}