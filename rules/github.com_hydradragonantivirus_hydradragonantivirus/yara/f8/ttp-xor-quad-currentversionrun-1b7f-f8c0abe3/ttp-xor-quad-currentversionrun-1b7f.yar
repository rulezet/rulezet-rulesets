rule TTP_XOR_QUAD_CurrentVersionRun_1b7f {
  strings:
    $key_1b7f = { 48 10 [2] 6c 1e [2] 47 32 [2] 69 10 [2] 7d 0b [2] 72 11 [2] 6c 0c [2] 6e 0d [2] 75 0b [2] 69 0c [2] 75 23 }

  condition:
    any of them
}