rule TTP_XOR_QUAD_CurrentVersionRun_0e0a {
  strings:
    $key_0e0a = { 5d 65 [2] 79 6b [2] 52 47 [2] 7c 65 [2] 68 7e [2] 67 64 [2] 79 79 [2] 7b 78 [2] 60 7e [2] 7c 79 [2] 60 56 }

  condition:
    any of them
}