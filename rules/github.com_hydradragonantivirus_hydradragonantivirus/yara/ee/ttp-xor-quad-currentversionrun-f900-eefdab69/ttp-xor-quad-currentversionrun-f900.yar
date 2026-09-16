rule TTP_XOR_QUAD_CurrentVersionRun_f900 {
  strings:
    $key_f900 = { aa 6f [2] 8e 61 [2] a5 4d [2] 8b 6f [2] 9f 74 [2] 90 6e [2] 8e 73 [2] 8c 72 [2] 97 74 [2] 8b 73 [2] 97 5c }

  condition:
    any of them
}