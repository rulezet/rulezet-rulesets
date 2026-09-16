rule TTP_XOR_QUAD_CurrentVersionRun_0132 {
  strings:
    $key_0132 = { 52 5d [2] 76 53 [2] 5d 7f [2] 73 5d [2] 67 46 [2] 68 5c [2] 76 41 [2] 74 40 [2] 6f 46 [2] 73 41 [2] 6f 6e }

  condition:
    any of them
}