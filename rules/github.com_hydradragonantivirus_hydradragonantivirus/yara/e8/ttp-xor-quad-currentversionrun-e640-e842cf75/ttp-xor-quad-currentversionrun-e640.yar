rule TTP_XOR_QUAD_CurrentVersionRun_e640 {
  strings:
    $key_e640 = { b5 2f [2] 91 21 [2] ba 0d [2] 94 2f [2] 80 34 [2] 8f 2e [2] 91 33 [2] 93 32 [2] 88 34 [2] 94 33 [2] 88 1c }

  condition:
    any of them
}