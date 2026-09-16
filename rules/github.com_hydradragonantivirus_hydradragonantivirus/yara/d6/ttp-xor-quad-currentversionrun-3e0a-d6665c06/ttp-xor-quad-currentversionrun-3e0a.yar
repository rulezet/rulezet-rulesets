rule TTP_XOR_QUAD_CurrentVersionRun_3e0a {
  strings:
    $key_3e0a = { 6d 65 [2] 49 6b [2] 62 47 [2] 4c 65 [2] 58 7e [2] 57 64 [2] 49 79 [2] 4b 78 [2] 50 7e [2] 4c 79 [2] 50 56 }

  condition:
    any of them
}