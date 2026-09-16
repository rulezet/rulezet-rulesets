rule TTP_XOR_MULT_DOSStub_7fbe {
  strings:
    $key_7fbe = { 2b d6 [2] 5f ce [2] 18 cc [2] 5f dd [2] 11 d1 [2] 1d db [2] 0a d0 [2] 11 9e [2] 2c }

  condition:
    any of them
}