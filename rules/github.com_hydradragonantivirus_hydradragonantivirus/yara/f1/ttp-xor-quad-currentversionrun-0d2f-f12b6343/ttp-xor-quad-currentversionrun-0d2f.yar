rule TTP_XOR_QUAD_CurrentVersionRun_0d2f {
  strings:
    $key_0d2f = { 5e 40 [2] 7a 4e [2] 51 62 [2] 7f 40 [2] 6b 5b [2] 64 41 [2] 7a 5c [2] 78 5d [2] 63 5b [2] 7f 5c [2] 63 73 }

  condition:
    any of them
}