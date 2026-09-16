rule TTP_XOR_MULT_DOSStub_cdbe {
  strings:
    $key_cdbe = { 99 d6 [2] ed ce [2] aa cc [2] ed dd [2] a3 d1 [2] af db [2] b8 d0 [2] a3 9e [2] 9e }

  condition:
    any of them
}