rule TTP_XOR_MULT_DOSStub_daad {
  strings:
    $key_daad = { 8e c5 [2] fa dd [2] bd df [2] fa ce [2] b4 c2 [2] b8 c8 [2] af c3 [2] b4 8d [2] 89 }

  condition:
    any of them
}