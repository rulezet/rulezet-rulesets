rule TTP_XOR_QUAD_CurrentVersionRun_500a {
  strings:
    $key_500a = { 03 65 [2] 27 6b [2] 0c 47 [2] 22 65 [2] 36 7e [2] 39 64 [2] 27 79 [2] 25 78 [2] 3e 7e [2] 22 79 [2] 3e 56 }

  condition:
    any of them
}