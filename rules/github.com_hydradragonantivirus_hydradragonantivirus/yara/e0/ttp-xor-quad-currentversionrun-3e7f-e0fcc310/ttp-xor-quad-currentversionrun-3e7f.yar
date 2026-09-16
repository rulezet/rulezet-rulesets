rule TTP_XOR_QUAD_CurrentVersionRun_3e7f {
  strings:
    $key_3e7f = { 6d 10 [2] 49 1e [2] 62 32 [2] 4c 10 [2] 58 0b [2] 57 11 [2] 49 0c [2] 4b 0d [2] 50 0b [2] 4c 0c [2] 50 23 }

  condition:
    any of them
}