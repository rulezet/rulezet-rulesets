rule TTP_XOR_QUAD_CurrentVersionRun_6c0d {
  strings:
    $key_6c0d = { 3f 62 [2] 1b 6c [2] 30 40 [2] 1e 62 [2] 0a 79 [2] 05 63 [2] 1b 7e [2] 19 7f [2] 02 79 [2] 1e 7e [2] 02 51 }

  condition:
    any of them
}