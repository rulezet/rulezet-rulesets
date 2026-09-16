rule TTP_XOR_QUAD_CurrentVersionRun_362d {
  strings:
    $key_362d = { 65 42 [2] 41 4c [2] 6a 60 [2] 44 42 [2] 50 59 [2] 5f 43 [2] 41 5e [2] 43 5f [2] 58 59 [2] 44 5e [2] 58 71 }

  condition:
    any of them
}