rule TTP_XOR_QUAD_CurrentVersionRun_630d {
  strings:
    $key_630d = { 30 62 [2] 14 6c [2] 3f 40 [2] 11 62 [2] 05 79 [2] 0a 63 [2] 14 7e [2] 16 7f [2] 0d 79 [2] 11 7e [2] 0d 51 }

  condition:
    any of them
}