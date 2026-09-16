rule TTP_XOR_QUAD_CurrentVersionRun_177d {
  strings:
    $key_177d = { 44 12 [2] 60 1c [2] 4b 30 [2] 65 12 [2] 71 09 [2] 7e 13 [2] 60 0e [2] 62 0f [2] 79 09 [2] 65 0e [2] 79 21 }

  condition:
    any of them
}