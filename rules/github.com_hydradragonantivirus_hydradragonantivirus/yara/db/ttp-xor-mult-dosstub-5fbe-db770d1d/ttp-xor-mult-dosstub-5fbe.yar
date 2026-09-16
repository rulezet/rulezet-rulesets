rule TTP_XOR_MULT_DOSStub_5fbe {
  strings:
    $key_5fbe = { 0b d6 [2] 7f ce [2] 38 cc [2] 7f dd [2] 31 d1 [2] 3d db [2] 2a d0 [2] 31 9e [2] 0c }

  condition:
    any of them
}