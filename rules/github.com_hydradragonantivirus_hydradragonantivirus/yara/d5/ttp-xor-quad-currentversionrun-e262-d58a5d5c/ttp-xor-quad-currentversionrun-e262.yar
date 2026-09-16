rule TTP_XOR_QUAD_CurrentVersionRun_e262 {
  strings:
    $key_e262 = { b1 0d [2] 95 03 [2] be 2f [2] 90 0d [2] 84 16 [2] 8b 0c [2] 95 11 [2] 97 10 [2] 8c 16 [2] 90 11 [2] 8c 3e }

  condition:
    any of them
}