rule TTP_XOR_QUAD_CurrentVersionRun_3c00 {
  strings:
    $key_3c00 = { 6f 6f [2] 4b 61 [2] 60 4d [2] 4e 6f [2] 5a 74 [2] 55 6e [2] 4b 73 [2] 49 72 [2] 52 74 [2] 4e 73 [2] 52 5c }

  condition:
    any of them
}