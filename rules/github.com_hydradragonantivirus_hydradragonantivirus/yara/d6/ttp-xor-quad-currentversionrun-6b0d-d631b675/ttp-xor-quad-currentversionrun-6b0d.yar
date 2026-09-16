rule TTP_XOR_QUAD_CurrentVersionRun_6b0d {
  strings:
    $key_6b0d = { 38 62 [2] 1c 6c [2] 37 40 [2] 19 62 [2] 0d 79 [2] 02 63 [2] 1c 7e [2] 1e 7f [2] 05 79 [2] 19 7e [2] 05 51 }

  condition:
    any of them
}