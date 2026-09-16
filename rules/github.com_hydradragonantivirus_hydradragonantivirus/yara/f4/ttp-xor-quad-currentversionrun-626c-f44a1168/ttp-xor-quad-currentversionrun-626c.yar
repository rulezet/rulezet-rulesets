rule TTP_XOR_QUAD_CurrentVersionRun_626c {
  strings:
    $key_626c = { 31 03 [2] 15 0d [2] 3e 21 [2] 10 03 [2] 04 18 [2] 0b 02 [2] 15 1f [2] 17 1e [2] 0c 18 [2] 10 1f [2] 0c 30 }

  condition:
    any of them
}