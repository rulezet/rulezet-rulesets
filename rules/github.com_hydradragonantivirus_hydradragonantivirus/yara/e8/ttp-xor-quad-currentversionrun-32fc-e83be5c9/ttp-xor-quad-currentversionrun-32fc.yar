rule TTP_XOR_QUAD_CurrentVersionRun_32fc {
  strings:
    $key_32fc = { 61 93 [2] 45 9d [2] 6e b1 [2] 40 93 [2] 54 88 [2] 5b 92 [2] 45 8f [2] 47 8e [2] 5c 88 [2] 40 8f [2] 5c a0 }

  condition:
    any of them
}