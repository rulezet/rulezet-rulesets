rule TTP_XOR_QUAD_CurrentVersionRun_0120 {
  strings:
    $key_0120 = { 52 4f [2] 76 41 [2] 5d 6d [2] 73 4f [2] 67 54 [2] 68 4e [2] 76 53 [2] 74 52 [2] 6f 54 [2] 73 53 [2] 6f 7c }

  condition:
    any of them
}