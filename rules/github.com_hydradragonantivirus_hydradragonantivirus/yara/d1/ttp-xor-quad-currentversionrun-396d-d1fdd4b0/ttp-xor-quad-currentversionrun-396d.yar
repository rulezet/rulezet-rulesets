rule TTP_XOR_QUAD_CurrentVersionRun_396d {
  strings:
    $key_396d = { 6a 02 [2] 4e 0c [2] 65 20 [2] 4b 02 [2] 5f 19 [2] 50 03 [2] 4e 1e [2] 4c 1f [2] 57 19 [2] 4b 1e [2] 57 31 }

  condition:
    any of them
}