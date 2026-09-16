rule TTP_XOR_QUAD_CurrentVersionRun_2e1c {
  strings:
    $key_2e1c = { 7d 73 [2] 59 7d [2] 72 51 [2] 5c 73 [2] 48 68 [2] 47 72 [2] 59 6f [2] 5b 6e [2] 40 68 [2] 5c 6f [2] 40 40 }

  condition:
    any of them
}