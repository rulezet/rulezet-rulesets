rule TTP_XOR_QUAD_CurrentVersionRun_147f {
  strings:
    $key_147f = { 47 10 [2] 63 1e [2] 48 32 [2] 66 10 [2] 72 0b [2] 7d 11 [2] 63 0c [2] 61 0d [2] 7a 0b [2] 66 0c [2] 7a 23 }

  condition:
    any of them
}