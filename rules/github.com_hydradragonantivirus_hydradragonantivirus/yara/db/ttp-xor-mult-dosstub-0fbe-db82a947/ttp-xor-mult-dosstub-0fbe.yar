rule TTP_XOR_MULT_DOSStub_0fbe {
  strings:
    $key_0fbe = { 5b d6 [2] 2f ce [2] 68 cc [2] 2f dd [2] 61 d1 [2] 6d db [2] 7a d0 [2] 61 9e [2] 5c }

  condition:
    any of them
}