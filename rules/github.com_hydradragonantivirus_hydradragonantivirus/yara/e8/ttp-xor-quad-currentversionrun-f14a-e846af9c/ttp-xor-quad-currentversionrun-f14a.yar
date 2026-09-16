rule TTP_XOR_QUAD_CurrentVersionRun_f14a {
  strings:
    $key_f14a = { a2 25 [2] 86 2b [2] ad 07 [2] 83 25 [2] 97 3e [2] 98 24 [2] 86 39 [2] 84 38 [2] 9f 3e [2] 83 39 [2] 9f 16 }

  condition:
    any of them
}