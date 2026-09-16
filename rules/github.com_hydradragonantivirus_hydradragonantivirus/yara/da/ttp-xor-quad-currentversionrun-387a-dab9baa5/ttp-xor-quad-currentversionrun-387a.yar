rule TTP_XOR_QUAD_CurrentVersionRun_387a {
  strings:
    $key_387a = { 6b 15 [2] 4f 1b [2] 64 37 [2] 4a 15 [2] 5e 0e [2] 51 14 [2] 4f 09 [2] 4d 08 [2] 56 0e [2] 4a 09 [2] 56 26 }

  condition:
    any of them
}