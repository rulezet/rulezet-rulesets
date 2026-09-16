rule TTP_XOR_QUAD_CurrentVersionRun_240c {
  strings:
    $key_240c = { 77 63 [2] 53 6d [2] 78 41 [2] 56 63 [2] 42 78 [2] 4d 62 [2] 53 7f [2] 51 7e [2] 4a 78 [2] 56 7f [2] 4a 50 }

  condition:
    any of them
}