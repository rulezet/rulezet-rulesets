rule TTP_XOR_QUAD_CurrentVersionRun_640d {
  strings:
    $key_640d = { 37 62 [2] 13 6c [2] 38 40 [2] 16 62 [2] 02 79 [2] 0d 63 [2] 13 7e [2] 11 7f [2] 0a 79 [2] 16 7e [2] 0a 51 }

  condition:
    any of them
}