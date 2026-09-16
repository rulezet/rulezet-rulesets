rule TTP_XOR_MULT_DOSStub_6fad {
  strings:
    $key_6fad = { 3b c5 [2] 4f dd [2] 08 df [2] 4f ce [2] 01 c2 [2] 0d c8 [2] 1a c3 [2] 01 8d [2] 3c }

  condition:
    any of them
}