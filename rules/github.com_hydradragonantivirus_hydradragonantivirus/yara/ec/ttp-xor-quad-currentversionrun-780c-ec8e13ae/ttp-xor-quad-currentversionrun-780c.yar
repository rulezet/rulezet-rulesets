rule TTP_XOR_QUAD_CurrentVersionRun_780c {
  strings:
    $key_780c = { 2b 63 [2] 0f 6d [2] 24 41 [2] 0a 63 [2] 1e 78 [2] 11 62 [2] 0f 7f [2] 0d 7e [2] 16 78 [2] 0a 7f [2] 16 50 }

  condition:
    any of them
}