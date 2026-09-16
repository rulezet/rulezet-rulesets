rule TTP_XOR_QUAD_CurrentVersionRun_28fd {
  strings:
    $key_28fd = { 7b 92 [2] 5f 9c [2] 74 b0 [2] 5a 92 [2] 4e 89 [2] 41 93 [2] 5f 8e [2] 5d 8f [2] 46 89 [2] 5a 8e [2] 46 a1 }

  condition:
    any of them
}