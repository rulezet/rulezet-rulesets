rule TTP_XOR_QUAD_CurrentVersionRun_206c {
  strings:
    $key_206c = { 73 03 [2] 57 0d [2] 7c 21 [2] 52 03 [2] 46 18 [2] 49 02 [2] 57 1f [2] 55 1e [2] 4e 18 [2] 52 1f [2] 4e 30 }

  condition:
    any of them
}