rule TTP_XOR_QUAD_CurrentVersionRun_3820 {
  strings:
    $key_3820 = { 6b 4f [2] 4f 41 [2] 64 6d [2] 4a 4f [2] 5e 54 [2] 51 4e [2] 4f 53 [2] 4d 52 [2] 56 54 [2] 4a 53 [2] 56 7c }

  condition:
    any of them
}