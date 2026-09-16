rule TTP_XOR_MULT_DOSStub_ceba {
  strings:
    $key_ceba = { 9a d2 [2] ee ca [2] a9 c8 [2] ee d9 [2] a0 d5 [2] ac df [2] bb d4 [2] a0 9a [2] 9d }

  condition:
    any of them
}