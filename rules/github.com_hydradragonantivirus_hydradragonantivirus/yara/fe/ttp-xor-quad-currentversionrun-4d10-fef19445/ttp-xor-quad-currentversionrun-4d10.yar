rule TTP_XOR_QUAD_CurrentVersionRun_4d10 {
  strings:
    $key_4d10 = { 1e 7f [2] 3a 71 [2] 11 5d [2] 3f 7f [2] 2b 64 [2] 24 7e [2] 3a 63 [2] 38 62 [2] 23 64 [2] 3f 63 [2] 23 4c }

  condition:
    any of them
}