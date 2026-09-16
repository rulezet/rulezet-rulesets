rule TTP_XOR_QUAD_CurrentVersionRun_3c6d {
  strings:
    $key_3c6d = { 6f 02 [2] 4b 0c [2] 60 20 [2] 4e 02 [2] 5a 19 [2] 55 03 [2] 4b 1e [2] 49 1f [2] 52 19 [2] 4e 1e [2] 52 31 }

  condition:
    any of them
}