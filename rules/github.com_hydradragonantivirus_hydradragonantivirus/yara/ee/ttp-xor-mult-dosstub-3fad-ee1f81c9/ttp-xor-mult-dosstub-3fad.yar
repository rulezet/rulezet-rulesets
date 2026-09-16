rule TTP_XOR_MULT_DOSStub_3fad {
  strings:
    $key_3fad = { 6b c5 [2] 1f dd [2] 58 df [2] 1f ce [2] 51 c2 [2] 5d c8 [2] 4a c3 [2] 51 8d [2] 6c }

  condition:
    any of them
}