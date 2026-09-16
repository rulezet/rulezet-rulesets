rule TTP_XOR_QUAD_CurrentVersionRun_75fd {
  strings:
    $key_75fd = { 26 92 [2] 02 9c [2] 29 b0 [2] 07 92 [2] 13 89 [2] 1c 93 [2] 02 8e [2] 00 8f [2] 1b 89 [2] 07 8e [2] 1b a1 }

  condition:
    any of them
}