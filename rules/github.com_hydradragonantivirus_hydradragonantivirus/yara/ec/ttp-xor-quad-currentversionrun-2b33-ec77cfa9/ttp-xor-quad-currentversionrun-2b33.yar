rule TTP_XOR_QUAD_CurrentVersionRun_2b33 {
  strings:
    $key_2b33 = { 78 5c [2] 5c 52 [2] 77 7e [2] 59 5c [2] 4d 47 [2] 42 5d [2] 5c 40 [2] 5e 41 [2] 45 47 [2] 59 40 [2] 45 6f }

  condition:
    any of them
}