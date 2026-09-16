rule TTP_XOR_QUAD_CurrentVersionRun_1600 {
  strings:
    $key_1600 = { 45 6f [2] 61 61 [2] 4a 4d [2] 64 6f [2] 70 74 [2] 7f 6e [2] 61 73 [2] 63 72 [2] 78 74 [2] 64 73 [2] 78 5c }

  condition:
    any of them
}