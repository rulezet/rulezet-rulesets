rule TTP_XOR_QUAD_CurrentVersionRun_f43d {
  strings:
    $key_f43d = { a7 52 [2] 83 5c [2] a8 70 [2] 86 52 [2] 92 49 [2] 9d 53 [2] 83 4e [2] 81 4f [2] 9a 49 [2] 86 4e [2] 9a 61 }

  condition:
    any of them
}