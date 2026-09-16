rule TTP_XOR_MULT_DOSStub_1fbe {
  strings:
    $key_1fbe = { 4b d6 [2] 3f ce [2] 78 cc [2] 3f dd [2] 71 d1 [2] 7d db [2] 6a d0 [2] 71 9e [2] 4c }

  condition:
    any of them
}