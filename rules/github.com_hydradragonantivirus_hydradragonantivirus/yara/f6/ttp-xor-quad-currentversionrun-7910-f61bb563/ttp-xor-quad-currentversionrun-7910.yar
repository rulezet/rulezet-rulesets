rule TTP_XOR_QUAD_CurrentVersionRun_7910 {
  strings:
    $key_7910 = { 2a 7f [2] 0e 71 [2] 25 5d [2] 0b 7f [2] 1f 64 [2] 10 7e [2] 0e 63 [2] 0c 62 [2] 17 64 [2] 0b 63 [2] 17 4c }

  condition:
    any of them
}