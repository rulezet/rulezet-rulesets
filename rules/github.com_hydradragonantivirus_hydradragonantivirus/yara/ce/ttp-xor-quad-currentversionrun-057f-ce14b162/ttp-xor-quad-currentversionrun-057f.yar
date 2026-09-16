rule TTP_XOR_QUAD_CurrentVersionRun_057f {
  strings:
    $key_057f = { 56 10 [2] 72 1e [2] 59 32 [2] 77 10 [2] 63 0b [2] 6c 11 [2] 72 0c [2] 70 0d [2] 6b 0b [2] 77 0c [2] 6b 23 }

  condition:
    any of them
}