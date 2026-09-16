rule TTP_XOR_QUAD_CurrentVersionRun_182d {
  strings:
    $key_182d = { 4b 42 [2] 6f 4c [2] 44 60 [2] 6a 42 [2] 7e 59 [2] 71 43 [2] 6f 5e [2] 6d 5f [2] 76 59 [2] 6a 5e [2] 76 71 }

  condition:
    any of them
}