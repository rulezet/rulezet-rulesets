rule TTP_XOR_QUAD_CurrentVersionRun_080d {
  strings:
    $key_080d = { 5b 62 [2] 7f 6c [2] 54 40 [2] 7a 62 [2] 6e 79 [2] 61 63 [2] 7f 7e [2] 7d 7f [2] 66 79 [2] 7a 7e [2] 66 51 }

  condition:
    any of them
}