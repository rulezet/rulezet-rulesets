rule TTP_XOR_MULT_DOSStub_3ead {
  strings:
    $key_3ead = { 6a c5 [2] 1e dd [2] 59 df [2] 1e ce [2] 50 c2 [2] 5c c8 [2] 4b c3 [2] 50 8d [2] 6d }

  condition:
    any of them
}