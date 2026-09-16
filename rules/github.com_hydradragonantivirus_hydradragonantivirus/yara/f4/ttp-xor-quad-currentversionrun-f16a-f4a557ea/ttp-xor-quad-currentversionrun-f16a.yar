rule TTP_XOR_QUAD_CurrentVersionRun_f16a {
  strings:
    $key_f16a = { a2 05 [2] 86 0b [2] ad 27 [2] 83 05 [2] 97 1e [2] 98 04 [2] 86 19 [2] 84 18 [2] 9f 1e [2] 83 19 [2] 9f 36 }

  condition:
    any of them
}