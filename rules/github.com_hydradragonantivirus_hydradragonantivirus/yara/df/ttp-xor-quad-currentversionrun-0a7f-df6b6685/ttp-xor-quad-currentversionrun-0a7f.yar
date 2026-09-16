rule TTP_XOR_QUAD_CurrentVersionRun_0a7f {
  strings:
    $key_0a7f = { 59 10 [2] 7d 1e [2] 56 32 [2] 78 10 [2] 6c 0b [2] 63 11 [2] 7d 0c [2] 7f 0d [2] 64 0b [2] 78 0c [2] 64 23 }

  condition:
    any of them
}