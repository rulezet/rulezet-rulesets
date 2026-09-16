rule TTP_XOR_QUAD_CurrentVersionRun_0a0d {
  strings:
    $key_0a0d = { 59 62 [2] 7d 6c [2] 56 40 [2] 78 62 [2] 6c 79 [2] 63 63 [2] 7d 7e [2] 7f 7f [2] 64 79 [2] 78 7e [2] 64 51 }

  condition:
    any of them
}