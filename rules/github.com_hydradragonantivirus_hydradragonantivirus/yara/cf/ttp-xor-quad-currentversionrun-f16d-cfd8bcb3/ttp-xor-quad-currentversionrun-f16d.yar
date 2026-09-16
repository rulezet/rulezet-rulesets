rule TTP_XOR_QUAD_CurrentVersionRun_f16d {
  strings:
    $key_f16d = { a2 02 [2] 86 0c [2] ad 20 [2] 83 02 [2] 97 19 [2] 98 03 [2] 86 1e [2] 84 1f [2] 9f 19 [2] 83 1e [2] 9f 31 }

  condition:
    any of them
}