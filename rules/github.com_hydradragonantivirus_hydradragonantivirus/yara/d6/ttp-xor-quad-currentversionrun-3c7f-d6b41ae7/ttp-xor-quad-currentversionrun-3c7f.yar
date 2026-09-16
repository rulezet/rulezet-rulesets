rule TTP_XOR_QUAD_CurrentVersionRun_3c7f {
  strings:
    $key_3c7f = { 6f 10 [2] 4b 1e [2] 60 32 [2] 4e 10 [2] 5a 0b [2] 55 11 [2] 4b 0c [2] 49 0d [2] 52 0b [2] 4e 0c [2] 52 23 }

  condition:
    any of them
}