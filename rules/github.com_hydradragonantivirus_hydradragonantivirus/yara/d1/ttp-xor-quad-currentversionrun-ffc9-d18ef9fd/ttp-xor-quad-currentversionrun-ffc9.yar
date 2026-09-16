rule TTP_XOR_QUAD_CurrentVersionRun_ffc9 {
  strings:
    $key_ffc9 = { ac a6 [2] 88 a8 [2] a3 84 [2] 8d a6 [2] 99 bd [2] 96 a7 [2] 88 ba [2] 8a bb [2] 91 bd [2] 8d ba [2] 91 95 }

  condition:
    any of them
}