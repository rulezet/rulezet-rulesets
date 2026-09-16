rule TTP_XOR_QUAD_CurrentVersionRun_62fc {
  strings:
    $key_62fc = { 31 93 [2] 15 9d [2] 3e b1 [2] 10 93 [2] 04 88 [2] 0b 92 [2] 15 8f [2] 17 8e [2] 0c 88 [2] 10 8f [2] 0c a0 }

  condition:
    any of them
}