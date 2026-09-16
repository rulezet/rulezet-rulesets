rule TTP_XOR_QUAD_CurrentVersionRun_e22d {
  strings:
    $key_e22d = { b1 42 [2] 95 4c [2] be 60 [2] 90 42 [2] 84 59 [2] 8b 43 [2] 95 5e [2] 97 5f [2] 8c 59 [2] 90 5e [2] 8c 71 }

  condition:
    any of them
}