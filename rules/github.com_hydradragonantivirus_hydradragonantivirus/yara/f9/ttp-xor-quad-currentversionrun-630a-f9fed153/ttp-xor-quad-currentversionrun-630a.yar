rule TTP_XOR_QUAD_CurrentVersionRun_630a {
  strings:
    $key_630a = { 30 65 [2] 14 6b [2] 3f 47 [2] 11 65 [2] 05 7e [2] 0a 64 [2] 14 79 [2] 16 78 [2] 0d 7e [2] 11 79 [2] 0d 56 }

  condition:
    any of them
}