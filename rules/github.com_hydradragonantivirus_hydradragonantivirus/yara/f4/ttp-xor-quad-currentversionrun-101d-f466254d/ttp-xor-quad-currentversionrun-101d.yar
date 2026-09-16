rule TTP_XOR_QUAD_CurrentVersionRun_101d {
  strings:
    $key_101d = { 43 72 [2] 67 7c [2] 4c 50 [2] 62 72 [2] 76 69 [2] 79 73 [2] 67 6e [2] 65 6f [2] 7e 69 [2] 62 6e [2] 7e 41 }

  condition:
    any of them
}