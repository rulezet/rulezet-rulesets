rule TTP_XOR_MULT_DOSStub_daa8 {
  strings:
    $key_daa8 = { 8e c0 [2] fa d8 [2] bd da [2] fa cb [2] b4 c7 [2] b8 cd [2] af c6 [2] b4 88 [2] 89 }

  condition:
    any of them
}