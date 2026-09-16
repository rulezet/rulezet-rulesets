rule TTP_XOR_MULT_DOSStub_2ead {
  strings:
    $key_2ead = { 7a c5 [2] 0e dd [2] 49 df [2] 0e ce [2] 40 c2 [2] 4c c8 [2] 5b c3 [2] 40 8d [2] 7d }

  condition:
    any of them
}