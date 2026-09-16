rule TTP_XOR_QUAD_CurrentVersionRun_26f3 {
  strings:
    $key_26f3 = { 75 9c [2] 51 92 [2] 7a be [2] 54 9c [2] 40 87 [2] 4f 9d [2] 51 80 [2] 53 81 [2] 48 87 [2] 54 80 [2] 48 af }

  condition:
    any of them
}