rule TTP_XOR_QUAD_CurrentVersionRun_f31e {
  strings:
    $key_f31e = { a0 71 [2] 84 7f [2] af 53 [2] 81 71 [2] 95 6a [2] 9a 70 [2] 84 6d [2] 86 6c [2] 9d 6a [2] 81 6d [2] 9d 42 }

  condition:
    any of them
}