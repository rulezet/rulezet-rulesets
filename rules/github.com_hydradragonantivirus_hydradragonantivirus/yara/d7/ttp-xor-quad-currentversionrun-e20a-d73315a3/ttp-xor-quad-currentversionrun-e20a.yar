rule TTP_XOR_QUAD_CurrentVersionRun_e20a {
  strings:
    $key_e20a = { b1 65 [2] 95 6b [2] be 47 [2] 90 65 [2] 84 7e [2] 8b 64 [2] 95 79 [2] 97 78 [2] 8c 7e [2] 90 79 [2] 8c 56 }

  condition:
    any of them
}