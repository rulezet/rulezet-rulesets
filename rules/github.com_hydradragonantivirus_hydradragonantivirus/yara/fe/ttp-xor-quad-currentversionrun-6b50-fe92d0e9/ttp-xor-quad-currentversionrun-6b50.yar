rule TTP_XOR_QUAD_CurrentVersionRun_6b50 {
  strings:
    $key_6b50 = { 38 3f [2] 1c 31 [2] 37 1d [2] 19 3f [2] 0d 24 [2] 02 3e [2] 1c 23 [2] 1e 22 [2] 05 24 [2] 19 23 [2] 05 0c }

  condition:
    any of them
}