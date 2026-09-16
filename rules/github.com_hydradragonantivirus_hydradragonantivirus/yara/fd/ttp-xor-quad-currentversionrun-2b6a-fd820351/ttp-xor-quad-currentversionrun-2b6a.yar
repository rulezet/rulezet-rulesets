rule TTP_XOR_QUAD_CurrentVersionRun_2b6a {
  strings:
    $key_2b6a = { 78 05 [2] 5c 0b [2] 77 27 [2] 59 05 [2] 4d 1e [2] 42 04 [2] 5c 19 [2] 5e 18 [2] 45 1e [2] 59 19 [2] 45 36 }

  condition:
    any of them
}