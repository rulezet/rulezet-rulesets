rule TTP_XOR_QUAD_CurrentVersionRun_f810 {
  strings:
    $key_f810 = { ab 7f [2] 8f 71 [2] a4 5d [2] 8a 7f [2] 9e 64 [2] 91 7e [2] 8f 63 [2] 8d 62 [2] 96 64 [2] 8a 63 [2] 96 4c }

  condition:
    any of them
}