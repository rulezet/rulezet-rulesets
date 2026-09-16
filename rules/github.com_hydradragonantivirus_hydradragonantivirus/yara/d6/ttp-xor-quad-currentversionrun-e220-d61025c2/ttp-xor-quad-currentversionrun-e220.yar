rule TTP_XOR_QUAD_CurrentVersionRun_e220 {
  strings:
    $key_e220 = { b1 4f [2] 95 41 [2] be 6d [2] 90 4f [2] 84 54 [2] 8b 4e [2] 95 53 [2] 97 52 [2] 8c 54 [2] 90 53 [2] 8c 7c }

  condition:
    any of them
}