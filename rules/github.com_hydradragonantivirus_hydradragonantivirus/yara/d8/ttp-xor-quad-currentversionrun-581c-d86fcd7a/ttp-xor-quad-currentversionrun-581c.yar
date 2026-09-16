rule TTP_XOR_QUAD_CurrentVersionRun_581c {
  strings:
    $key_581c = { 0b 73 [2] 2f 7d [2] 04 51 [2] 2a 73 [2] 3e 68 [2] 31 72 [2] 2f 6f [2] 2d 6e [2] 36 68 [2] 2a 6f [2] 36 40 }

  condition:
    any of them
}