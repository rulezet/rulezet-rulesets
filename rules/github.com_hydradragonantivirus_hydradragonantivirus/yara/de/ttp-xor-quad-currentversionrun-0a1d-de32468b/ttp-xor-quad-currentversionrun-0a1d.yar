rule TTP_XOR_QUAD_CurrentVersionRun_0a1d {
  strings:
    $key_0a1d = { 59 72 [2] 7d 7c [2] 56 50 [2] 78 72 [2] 6c 69 [2] 63 73 [2] 7d 6e [2] 7f 6f [2] 64 69 [2] 78 6e [2] 64 41 }

  condition:
    any of them
}