rule TTP_XOR_QUAD_CurrentVersionRun_010c {
  strings:
    $key_010c = { 52 63 [2] 76 6d [2] 5d 41 [2] 73 63 [2] 67 78 [2] 68 62 [2] 76 7f [2] 74 7e [2] 6f 78 [2] 73 7f [2] 6f 50 }

  condition:
    any of them
}