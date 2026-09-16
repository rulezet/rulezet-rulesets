rule TTP_XOR_QUAD_CurrentVersionRun_191c {
  strings:
    $key_191c = { 4a 73 [2] 6e 7d [2] 45 51 [2] 6b 73 [2] 7f 68 [2] 70 72 [2] 6e 6f [2] 6c 6e [2] 77 68 [2] 6b 6f [2] 77 40 }

  condition:
    any of them
}