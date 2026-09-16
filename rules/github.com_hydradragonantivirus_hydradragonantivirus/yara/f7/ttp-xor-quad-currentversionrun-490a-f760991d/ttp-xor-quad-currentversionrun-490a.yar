rule TTP_XOR_QUAD_CurrentVersionRun_490a {
  strings:
    $key_490a = { 1a 65 [2] 3e 6b [2] 15 47 [2] 3b 65 [2] 2f 7e [2] 20 64 [2] 3e 79 [2] 3c 78 [2] 27 7e [2] 3b 79 [2] 27 56 }

  condition:
    any of them
}