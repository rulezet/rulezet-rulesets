rule TTP_XOR_QUAD_CurrentVersionRun_042d {
  strings:
    $key_042d = { 57 42 [2] 73 4c [2] 58 60 [2] 76 42 [2] 62 59 [2] 6d 43 [2] 73 5e [2] 71 5f [2] 6a 59 [2] 76 5e [2] 6a 71 }

  condition:
    any of them
}