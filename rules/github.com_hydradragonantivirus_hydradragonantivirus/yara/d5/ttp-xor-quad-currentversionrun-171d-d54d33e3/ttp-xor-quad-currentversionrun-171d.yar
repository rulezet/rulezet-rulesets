rule TTP_XOR_QUAD_CurrentVersionRun_171d {
  strings:
    $key_171d = { 44 72 [2] 60 7c [2] 4b 50 [2] 65 72 [2] 71 69 [2] 7e 73 [2] 60 6e [2] 62 6f [2] 79 69 [2] 65 6e [2] 79 41 }

  condition:
    any of them
}