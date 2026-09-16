rule TTP_XOR_QUAD_CurrentVersionRun_f23e {
  strings:
    $key_f23e = { a1 51 [2] 85 5f [2] ae 73 [2] 80 51 [2] 94 4a [2] 9b 50 [2] 85 4d [2] 87 4c [2] 9c 4a [2] 80 4d [2] 9c 62 }

  condition:
    any of them
}