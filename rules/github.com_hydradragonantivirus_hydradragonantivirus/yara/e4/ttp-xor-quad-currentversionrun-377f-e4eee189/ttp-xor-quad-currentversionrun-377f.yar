rule TTP_XOR_QUAD_CurrentVersionRun_377f {
  strings:
    $key_377f = { 64 10 [2] 40 1e [2] 6b 32 [2] 45 10 [2] 51 0b [2] 5e 11 [2] 40 0c [2] 42 0d [2] 59 0b [2] 45 0c [2] 59 23 }

  condition:
    any of them
}