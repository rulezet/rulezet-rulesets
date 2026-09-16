rule TTP_XOR_QUAD_CurrentVersionRun_3e1c {
  strings:
    $key_3e1c = { 6d 73 [2] 49 7d [2] 62 51 [2] 4c 73 [2] 58 68 [2] 57 72 [2] 49 6f [2] 4b 6e [2] 50 68 [2] 4c 6f [2] 50 40 }

  condition:
    any of them
}