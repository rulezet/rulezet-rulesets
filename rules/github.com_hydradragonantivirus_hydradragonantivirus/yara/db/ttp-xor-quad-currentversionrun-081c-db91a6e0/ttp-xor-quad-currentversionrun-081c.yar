rule TTP_XOR_QUAD_CurrentVersionRun_081c {
  strings:
    $key_081c = { 5b 73 [2] 7f 7d [2] 54 51 [2] 7a 73 [2] 6e 68 [2] 61 72 [2] 7f 6f [2] 7d 6e [2] 66 68 [2] 7a 6f [2] 66 40 }

  condition:
    any of them
}