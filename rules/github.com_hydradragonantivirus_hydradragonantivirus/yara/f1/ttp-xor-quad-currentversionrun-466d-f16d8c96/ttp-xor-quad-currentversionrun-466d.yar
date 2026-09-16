rule TTP_XOR_QUAD_CurrentVersionRun_466d {
  strings:
    $key_466d = { 15 02 [2] 31 0c [2] 1a 20 [2] 34 02 [2] 20 19 [2] 2f 03 [2] 31 1e [2] 33 1f [2] 28 19 [2] 34 1e [2] 28 31 }

  condition:
    any of them
}