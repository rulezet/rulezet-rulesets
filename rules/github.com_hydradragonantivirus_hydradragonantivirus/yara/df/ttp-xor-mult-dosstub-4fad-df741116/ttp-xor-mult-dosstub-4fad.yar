rule TTP_XOR_MULT_DOSStub_4fad {
  strings:
    $key_4fad = { 1b c5 [2] 6f dd [2] 28 df [2] 6f ce [2] 21 c2 [2] 2d c8 [2] 3a c3 [2] 21 8d [2] 1c }

  condition:
    any of them
}