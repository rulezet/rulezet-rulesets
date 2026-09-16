rule TTP_XOR_QUAD_CurrentVersionRun_e27d {
  strings:
    $key_e27d = { b1 12 [2] 95 1c [2] be 30 [2] 90 12 [2] 84 09 [2] 8b 13 [2] 95 0e [2] 97 0f [2] 8c 09 [2] 90 0e [2] 8c 21 }

  condition:
    any of them
}