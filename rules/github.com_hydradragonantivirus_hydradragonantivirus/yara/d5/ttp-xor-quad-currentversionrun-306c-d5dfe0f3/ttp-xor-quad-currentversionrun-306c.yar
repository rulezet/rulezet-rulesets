rule TTP_XOR_QUAD_CurrentVersionRun_306c {
  strings:
    $key_306c = { 63 03 [2] 47 0d [2] 6c 21 [2] 42 03 [2] 56 18 [2] 59 02 [2] 47 1f [2] 45 1e [2] 5e 18 [2] 42 1f [2] 5e 30 }

  condition:
    any of them
}