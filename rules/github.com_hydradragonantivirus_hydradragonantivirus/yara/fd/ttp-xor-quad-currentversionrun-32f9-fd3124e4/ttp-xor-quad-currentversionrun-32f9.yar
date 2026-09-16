rule TTP_XOR_QUAD_CurrentVersionRun_32f9 {
  strings:
    $key_32f9 = { 61 96 [2] 45 98 [2] 6e b4 [2] 40 96 [2] 54 8d [2] 5b 97 [2] 45 8a [2] 47 8b [2] 5c 8d [2] 40 8a [2] 5c a5 }

  condition:
    any of them
}