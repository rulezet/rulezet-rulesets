rule TTP_XOR_QUAD_CurrentVersionRun_06f3 {
  strings:
    $key_06f3 = { 55 9c [2] 71 92 [2] 5a be [2] 74 9c [2] 60 87 [2] 6f 9d [2] 71 80 [2] 73 81 [2] 68 87 [2] 74 80 [2] 68 af }

  condition:
    any of them
}