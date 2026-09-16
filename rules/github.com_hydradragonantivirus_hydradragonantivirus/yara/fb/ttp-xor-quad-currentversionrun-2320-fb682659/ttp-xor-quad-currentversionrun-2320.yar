rule TTP_XOR_QUAD_CurrentVersionRun_2320 {
  strings:
    $key_2320 = { 70 4f [2] 54 41 [2] 7f 6d [2] 51 4f [2] 45 54 [2] 4a 4e [2] 54 53 [2] 56 52 [2] 4d 54 [2] 51 53 [2] 4d 7c }

  condition:
    any of them
}