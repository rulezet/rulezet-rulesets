rule TTP_XOR_QUAD_CurrentVersionRun_e85d {
  strings:
    $key_e85d = { bb 32 [2] 9f 3c [2] b4 10 [2] 9a 32 [2] 8e 29 [2] 81 33 [2] 9f 2e [2] 9d 2f [2] 86 29 [2] 9a 2e [2] 86 01 }

  condition:
    any of them
}