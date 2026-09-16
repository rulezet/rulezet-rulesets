rule TTP_XOR_MULT_DOSStub_4fbe {
  strings:
    $key_4fbe = { 1b d6 [2] 6f ce [2] 28 cc [2] 6f dd [2] 21 d1 [2] 2d db [2] 3a d0 [2] 21 9e [2] 1c }

  condition:
    any of them
}