rule TTP_XOR_QUAD_CurrentVersionRun_f120 {
  strings:
    $key_f120 = { a2 4f [2] 86 41 [2] ad 6d [2] 83 4f [2] 97 54 [2] 98 4e [2] 86 53 [2] 84 52 [2] 9f 54 [2] 83 53 [2] 9f 7c }

  condition:
    any of them
}