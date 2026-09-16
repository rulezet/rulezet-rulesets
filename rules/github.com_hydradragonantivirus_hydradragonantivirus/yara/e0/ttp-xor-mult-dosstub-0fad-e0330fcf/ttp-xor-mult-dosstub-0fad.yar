rule TTP_XOR_MULT_DOSStub_0fad {
  strings:
    $key_0fad = { 5b c5 [2] 2f dd [2] 68 df [2] 2f ce [2] 61 c2 [2] 6d c8 [2] 7a c3 [2] 61 8d [2] 5c }

  condition:
    any of them
}