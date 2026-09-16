rule TTP_XOR_QUAD_CurrentVersionRun_571c {
  strings:
    $key_571c = { 04 73 [2] 20 7d [2] 0b 51 [2] 25 73 [2] 31 68 [2] 3e 72 [2] 20 6f [2] 22 6e [2] 39 68 [2] 25 6f [2] 39 40 }

  condition:
    any of them
}