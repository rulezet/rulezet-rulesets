rule TTP_XOR_QUAD_CurrentVersionRun_407f {
  strings:
    $key_407f = { 13 10 [2] 37 1e [2] 1c 32 [2] 32 10 [2] 26 0b [2] 29 11 [2] 37 0c [2] 35 0d [2] 2e 0b [2] 32 0c [2] 2e 23 }

  condition:
    any of them
}