rule TTP_XOR_QUAD_CurrentVersionRun_0d7f {
  strings:
    $key_0d7f = { 5e 10 [2] 7a 1e [2] 51 32 [2] 7f 10 [2] 6b 0b [2] 64 11 [2] 7a 0c [2] 78 0d [2] 63 0b [2] 7f 0c [2] 63 23 }

  condition:
    any of them
}