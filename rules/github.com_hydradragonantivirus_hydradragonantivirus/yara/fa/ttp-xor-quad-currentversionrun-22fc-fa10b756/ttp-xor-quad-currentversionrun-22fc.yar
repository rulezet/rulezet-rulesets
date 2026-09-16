rule TTP_XOR_QUAD_CurrentVersionRun_22fc {
  strings:
    $key_22fc = { 71 93 [2] 55 9d [2] 7e b1 [2] 50 93 [2] 44 88 [2] 4b 92 [2] 55 8f [2] 57 8e [2] 4c 88 [2] 50 8f [2] 4c a0 }

  condition:
    any of them
}