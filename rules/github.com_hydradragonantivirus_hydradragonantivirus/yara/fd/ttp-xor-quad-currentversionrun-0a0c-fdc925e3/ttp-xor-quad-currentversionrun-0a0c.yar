rule TTP_XOR_QUAD_CurrentVersionRun_0a0c {
  strings:
    $key_0a0c = { 59 63 [2] 7d 6d [2] 56 41 [2] 78 63 [2] 6c 78 [2] 63 62 [2] 7d 7f [2] 7f 7e [2] 64 78 [2] 78 7f [2] 64 50 }

  condition:
    any of them
}