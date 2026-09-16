rule TTP_XOR_MULT_DOSStub_7ead {
  strings:
    $key_7ead = { 2a c5 [2] 5e dd [2] 19 df [2] 5e ce [2] 10 c2 [2] 1c c8 [2] 0b c3 [2] 10 8d [2] 2d }

  condition:
    any of them
}