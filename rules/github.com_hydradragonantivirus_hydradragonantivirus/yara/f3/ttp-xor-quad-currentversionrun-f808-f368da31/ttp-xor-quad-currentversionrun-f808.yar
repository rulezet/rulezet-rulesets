rule TTP_XOR_QUAD_CurrentVersionRun_f808 {
  strings:
    $key_f808 = { ab 67 [2] 8f 69 [2] a4 45 [2] 8a 67 [2] 9e 7c [2] 91 66 [2] 8f 7b [2] 8d 7a [2] 96 7c [2] 8a 7b [2] 96 54 }

  condition:
    any of them
}