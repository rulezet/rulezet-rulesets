rule TTP_XOR_QUAD_CurrentVersionRun_790d {
  strings:
    $key_790d = { 2a 62 [2] 0e 6c [2] 25 40 [2] 0b 62 [2] 1f 79 [2] 10 63 [2] 0e 7e [2] 0c 7f [2] 17 79 [2] 0b 7e [2] 17 51 }

  condition:
    any of them
}