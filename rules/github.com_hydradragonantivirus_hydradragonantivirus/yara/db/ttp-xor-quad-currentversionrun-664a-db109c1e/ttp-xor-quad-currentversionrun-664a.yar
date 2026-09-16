rule TTP_XOR_QUAD_CurrentVersionRun_664a {
  strings:
    $key_664a = { 35 25 [2] 11 2b [2] 3a 07 [2] 14 25 [2] 00 3e [2] 0f 24 [2] 11 39 [2] 13 38 [2] 08 3e [2] 14 39 [2] 08 16 }

  condition:
    any of them
}