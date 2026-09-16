rule TTP_XOR_QUAD_CurrentVersionRun_2b7f {
  strings:
    $key_2b7f = { 78 10 [2] 5c 1e [2] 77 32 [2] 59 10 [2] 4d 0b [2] 42 11 [2] 5c 0c [2] 5e 0d [2] 45 0b [2] 59 0c [2] 45 23 }

  condition:
    any of them
}