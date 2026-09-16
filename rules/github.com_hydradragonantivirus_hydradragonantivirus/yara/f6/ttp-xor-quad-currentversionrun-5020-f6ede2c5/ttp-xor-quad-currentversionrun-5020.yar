rule TTP_XOR_QUAD_CurrentVersionRun_5020 {
  strings:
    $key_5020 = { 03 4f [2] 27 41 [2] 0c 6d [2] 22 4f [2] 36 54 [2] 39 4e [2] 27 53 [2] 25 52 [2] 3e 54 [2] 22 53 [2] 3e 7c }

  condition:
    any of them
}