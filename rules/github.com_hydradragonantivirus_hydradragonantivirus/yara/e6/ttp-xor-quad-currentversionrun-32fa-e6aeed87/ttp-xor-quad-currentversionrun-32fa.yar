rule TTP_XOR_QUAD_CurrentVersionRun_32fa {
  strings:
    $key_32fa = { 61 95 [2] 45 9b [2] 6e b7 [2] 40 95 [2] 54 8e [2] 5b 94 [2] 45 89 [2] 47 88 [2] 5c 8e [2] 40 89 [2] 5c a6 }

  condition:
    any of them
}