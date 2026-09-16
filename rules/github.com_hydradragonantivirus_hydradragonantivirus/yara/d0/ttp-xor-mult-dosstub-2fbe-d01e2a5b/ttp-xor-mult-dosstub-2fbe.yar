rule TTP_XOR_MULT_DOSStub_2fbe {
  strings:
    $key_2fbe = { 7b d6 [2] 0f ce [2] 48 cc [2] 0f dd [2] 41 d1 [2] 4d db [2] 5a d0 [2] 41 9e [2] 7c }

  condition:
    any of them
}