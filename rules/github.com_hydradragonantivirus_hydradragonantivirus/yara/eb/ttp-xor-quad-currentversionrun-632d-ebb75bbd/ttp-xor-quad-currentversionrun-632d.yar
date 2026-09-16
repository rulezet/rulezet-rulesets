rule TTP_XOR_QUAD_CurrentVersionRun_632d {
  strings:
    $key_632d = { 30 42 [2] 14 4c [2] 3f 60 [2] 11 42 [2] 05 59 [2] 0a 43 [2] 14 5e [2] 16 5f [2] 0d 59 [2] 11 5e [2] 0d 71 }

  condition:
    any of them
}