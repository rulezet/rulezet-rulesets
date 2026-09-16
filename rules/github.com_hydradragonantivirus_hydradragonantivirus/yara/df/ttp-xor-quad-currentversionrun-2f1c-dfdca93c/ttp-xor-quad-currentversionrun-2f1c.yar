rule TTP_XOR_QUAD_CurrentVersionRun_2f1c {
  strings:
    $key_2f1c = { 7c 73 [2] 58 7d [2] 73 51 [2] 5d 73 [2] 49 68 [2] 46 72 [2] 58 6f [2] 5a 6e [2] 41 68 [2] 5d 6f [2] 41 40 }

  condition:
    any of them
}