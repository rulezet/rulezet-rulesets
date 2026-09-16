rule TTP_XOR_QUAD_CurrentVersionRun_6b0c {
  strings:
    $key_6b0c = { 38 63 [2] 1c 6d [2] 37 41 [2] 19 63 [2] 0d 78 [2] 02 62 [2] 1c 7f [2] 1e 7e [2] 05 78 [2] 19 7f [2] 05 50 }

  condition:
    any of them
}