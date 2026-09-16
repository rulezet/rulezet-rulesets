rule TTP_XOR_QUAD_CurrentVersionRun_157d {
  strings:
    $key_157d = { 46 12 [2] 62 1c [2] 49 30 [2] 67 12 [2] 73 09 [2] 7c 13 [2] 62 0e [2] 60 0f [2] 7b 09 [2] 67 0e [2] 7b 21 }

  condition:
    any of them
}