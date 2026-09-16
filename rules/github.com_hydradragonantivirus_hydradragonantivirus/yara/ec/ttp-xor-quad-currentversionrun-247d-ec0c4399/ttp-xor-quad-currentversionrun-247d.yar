rule TTP_XOR_QUAD_CurrentVersionRun_247d {
  strings:
    $key_247d = { 77 12 [2] 53 1c [2] 78 30 [2] 56 12 [2] 42 09 [2] 4d 13 [2] 53 0e [2] 51 0f [2] 4a 09 [2] 56 0e [2] 4a 21 }

  condition:
    any of them
}