rule TTP_XOR_QUAD_CurrentVersionRun_221d {
  strings:
    $key_221d = { 71 72 [2] 55 7c [2] 7e 50 [2] 50 72 [2] 44 69 [2] 4b 73 [2] 55 6e [2] 57 6f [2] 4c 69 [2] 50 6e [2] 4c 41 }

  condition:
    any of them
}