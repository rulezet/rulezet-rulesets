rule TTP_XOR_QUAD_CurrentVersionRun_306d {
  strings:
    $key_306d = { 63 02 [2] 47 0c [2] 6c 20 [2] 42 02 [2] 56 19 [2] 59 03 [2] 47 1e [2] 45 1f [2] 5e 19 [2] 42 1e [2] 5e 31 }

  condition:
    any of them
}