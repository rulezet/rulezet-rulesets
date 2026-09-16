rule TTP_XOR_QUAD_CurrentVersionRun_f60d {
  strings:
    $key_f60d = { a5 62 [2] 81 6c [2] aa 40 [2] 84 62 [2] 90 79 [2] 9f 63 [2] 81 7e [2] 83 7f [2] 98 79 [2] 84 7e [2] 98 51 }

  condition:
    any of them
}