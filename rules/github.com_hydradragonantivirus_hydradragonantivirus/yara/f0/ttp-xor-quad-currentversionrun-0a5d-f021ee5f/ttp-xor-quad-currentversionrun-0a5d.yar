rule TTP_XOR_QUAD_CurrentVersionRun_0a5d {
  strings:
    $key_0a5d = { 59 32 [2] 7d 3c [2] 56 10 [2] 78 32 [2] 6c 29 [2] 63 33 [2] 7d 2e [2] 7f 2f [2] 64 29 [2] 78 2e [2] 64 01 }

  condition:
    any of them
}