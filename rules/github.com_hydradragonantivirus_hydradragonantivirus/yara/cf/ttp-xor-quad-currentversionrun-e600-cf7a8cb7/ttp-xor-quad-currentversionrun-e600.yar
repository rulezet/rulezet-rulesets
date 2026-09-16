rule TTP_XOR_QUAD_CurrentVersionRun_e600 {
  strings:
    $key_e600 = { b5 6f [2] 91 61 [2] ba 4d [2] 94 6f [2] 80 74 [2] 8f 6e [2] 91 73 [2] 93 72 [2] 88 74 [2] 94 73 [2] 88 5c }

  condition:
    any of them
}