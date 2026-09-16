rule TTP_XOR_QUAD_CurrentVersionRun_2b6c {
  strings:
    $key_2b6c = { 78 03 [2] 5c 0d [2] 77 21 [2] 59 03 [2] 4d 18 [2] 42 02 [2] 5c 1f [2] 5e 1e [2] 45 18 [2] 59 1f [2] 45 30 }

  condition:
    any of them
}