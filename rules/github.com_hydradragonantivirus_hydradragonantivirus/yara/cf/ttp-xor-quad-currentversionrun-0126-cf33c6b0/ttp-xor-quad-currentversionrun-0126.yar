rule TTP_XOR_QUAD_CurrentVersionRun_0126 {
  strings:
    $key_0126 = { 52 49 [2] 76 47 [2] 5d 6b [2] 73 49 [2] 67 52 [2] 68 48 [2] 76 55 [2] 74 54 [2] 6f 52 [2] 73 55 [2] 6f 7a }

  condition:
    any of them
}