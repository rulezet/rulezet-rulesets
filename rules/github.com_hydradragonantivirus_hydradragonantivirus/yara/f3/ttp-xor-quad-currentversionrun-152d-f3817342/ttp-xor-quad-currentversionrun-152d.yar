rule TTP_XOR_QUAD_CurrentVersionRun_152d {
  strings:
    $key_152d = { 46 42 [2] 62 4c [2] 49 60 [2] 67 42 [2] 73 59 [2] 7c 43 [2] 62 5e [2] 60 5f [2] 7b 59 [2] 67 5e [2] 7b 71 }

  condition:
    any of them
}