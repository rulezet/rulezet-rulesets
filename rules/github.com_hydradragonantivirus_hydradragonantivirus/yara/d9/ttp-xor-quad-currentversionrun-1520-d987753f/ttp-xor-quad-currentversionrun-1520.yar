rule TTP_XOR_QUAD_CurrentVersionRun_1520 {
  strings:
    $key_1520 = { 46 4f [2] 62 41 [2] 49 6d [2] 67 4f [2] 73 54 [2] 7c 4e [2] 62 53 [2] 60 52 [2] 7b 54 [2] 67 53 [2] 7b 7c }

  condition:
    any of them
}