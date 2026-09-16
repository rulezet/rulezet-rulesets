rule TTP_XOR_QUAD_CurrentVersionRun_7c7f {
  strings:
    $key_7c7f = { 2f 10 [2] 0b 1e [2] 20 32 [2] 0e 10 [2] 1a 0b [2] 15 11 [2] 0b 0c [2] 09 0d [2] 12 0b [2] 0e 0c [2] 12 23 }

  condition:
    any of them
}