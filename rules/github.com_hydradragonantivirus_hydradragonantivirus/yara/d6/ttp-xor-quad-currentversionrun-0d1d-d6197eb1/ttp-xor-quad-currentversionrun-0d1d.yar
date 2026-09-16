rule TTP_XOR_QUAD_CurrentVersionRun_0d1d {
  strings:
    $key_0d1d = { 5e 72 [2] 7a 7c [2] 51 50 [2] 7f 72 [2] 6b 69 [2] 64 73 [2] 7a 6e [2] 78 6f [2] 63 69 [2] 7f 6e [2] 63 41 }

  condition:
    any of them
}