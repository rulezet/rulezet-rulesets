rule TTP_XOR_QUAD_CurrentVersionRun_f820 {
  strings:
    $key_f820 = { ab 4f [2] 8f 41 [2] a4 6d [2] 8a 4f [2] 9e 54 [2] 91 4e [2] 8f 53 [2] 8d 52 [2] 96 54 [2] 8a 53 [2] 96 7c }

  condition:
    any of them
}