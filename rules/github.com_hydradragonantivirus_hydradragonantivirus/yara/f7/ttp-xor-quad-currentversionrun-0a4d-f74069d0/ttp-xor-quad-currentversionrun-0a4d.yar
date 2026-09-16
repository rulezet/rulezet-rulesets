rule TTP_XOR_QUAD_CurrentVersionRun_0a4d {
  strings:
    $key_0a4d = { 59 22 [2] 7d 2c [2] 56 00 [2] 78 22 [2] 6c 39 [2] 63 23 [2] 7d 3e [2] 7f 3f [2] 64 39 [2] 78 3e [2] 64 11 }

  condition:
    any of them
}