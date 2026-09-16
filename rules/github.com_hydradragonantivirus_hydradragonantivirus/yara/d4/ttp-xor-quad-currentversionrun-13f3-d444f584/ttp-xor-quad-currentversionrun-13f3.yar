rule TTP_XOR_QUAD_CurrentVersionRun_13f3 {
  strings:
    $key_13f3 = { 40 9c [2] 64 92 [2] 4f be [2] 61 9c [2] 75 87 [2] 7a 9d [2] 64 80 [2] 66 81 [2] 7d 87 [2] 61 80 [2] 7d af }

  condition:
    any of them
}