rule TTP_XOR_QUAD_CurrentVersionRun_e560 {
  strings:
    $key_e560 = { b6 0f [2] 92 01 [2] b9 2d [2] 97 0f [2] 83 14 [2] 8c 0e [2] 92 13 [2] 90 12 [2] 8b 14 [2] 97 13 [2] 8b 3c }

  condition:
    any of them
}