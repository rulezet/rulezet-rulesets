rule TTP_XOR_QUAD_CurrentVersionRun_062d {
  strings:
    $key_062d = { 55 42 [2] 71 4c [2] 5a 60 [2] 74 42 [2] 60 59 [2] 6f 43 [2] 71 5e [2] 73 5f [2] 68 59 [2] 74 5e [2] 68 71 }

  condition:
    any of them
}