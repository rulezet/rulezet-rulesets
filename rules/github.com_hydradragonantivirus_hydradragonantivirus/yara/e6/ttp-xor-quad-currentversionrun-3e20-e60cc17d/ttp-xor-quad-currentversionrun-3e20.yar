rule TTP_XOR_QUAD_CurrentVersionRun_3e20 {
  strings:
    $key_3e20 = { 6d 4f [2] 49 41 [2] 62 6d [2] 4c 4f [2] 58 54 [2] 57 4e [2] 49 53 [2] 4b 52 [2] 50 54 [2] 4c 53 [2] 50 7c }

  condition:
    any of them
}