rule TTP_XOR_MULT_DOSStub_dfbe {
  strings:
    $key_dfbe = { 8b d6 [2] ff ce [2] b8 cc [2] ff dd [2] b1 d1 [2] bd db [2] aa d0 [2] b1 9e [2] 8c }

  condition:
    any of them
}