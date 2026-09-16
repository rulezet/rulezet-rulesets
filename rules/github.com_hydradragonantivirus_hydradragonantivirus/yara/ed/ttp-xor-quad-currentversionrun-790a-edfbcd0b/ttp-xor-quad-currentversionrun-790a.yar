rule TTP_XOR_QUAD_CurrentVersionRun_790a {
  strings:
    $key_790a = { 2a 65 [2] 0e 6b [2] 25 47 [2] 0b 65 [2] 1f 7e [2] 10 64 [2] 0e 79 [2] 0c 78 [2] 17 7e [2] 0b 79 [2] 17 56 }

  condition:
    any of them
}