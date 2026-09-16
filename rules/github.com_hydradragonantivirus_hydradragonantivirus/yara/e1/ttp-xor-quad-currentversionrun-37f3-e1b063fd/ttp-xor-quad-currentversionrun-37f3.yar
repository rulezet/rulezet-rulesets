rule TTP_XOR_QUAD_CurrentVersionRun_37f3 {
  strings:
    $key_37f3 = { 64 9c [2] 40 92 [2] 6b be [2] 45 9c [2] 51 87 [2] 5e 9d [2] 40 80 [2] 42 81 [2] 59 87 [2] 45 80 [2] 59 af }

  condition:
    any of them
}