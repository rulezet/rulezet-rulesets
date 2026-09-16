rule TTP_XOR_QUAD_CurrentVersionRun_e251 {
  strings:
    $key_e251 = { b1 3e [2] 95 30 [2] be 1c [2] 90 3e [2] 84 25 [2] 8b 3f [2] 95 22 [2] 97 23 [2] 8c 25 [2] 90 22 [2] 8c 0d }

  condition:
    any of them
}