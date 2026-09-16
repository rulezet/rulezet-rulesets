rule TTP_XOR_QUAD_CurrentVersionRun_e223 {
  strings:
    $key_e223 = { b1 4c [2] 95 42 [2] be 6e [2] 90 4c [2] 84 57 [2] 8b 4d [2] 95 50 [2] 97 51 [2] 8c 57 [2] 90 50 [2] 8c 7f }

  condition:
    any of them
}