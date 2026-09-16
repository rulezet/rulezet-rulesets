rule TTP_XOR_QUAD_CurrentVersionRun_017d {
  strings:
    $key_017d = { 52 12 [2] 76 1c [2] 5d 30 [2] 73 12 [2] 67 09 [2] 68 13 [2] 76 0e [2] 74 0f [2] 6f 09 [2] 73 0e [2] 6f 21 }

  condition:
    any of them
}