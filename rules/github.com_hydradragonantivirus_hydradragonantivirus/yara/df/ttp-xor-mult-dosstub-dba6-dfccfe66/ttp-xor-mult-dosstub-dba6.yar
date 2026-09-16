rule TTP_XOR_MULT_DOSStub_dba6 {
  strings:
    $key_dba6 = { 8f ce [2] fb d6 [2] bc d4 [2] fb c5 [2] b5 c9 [2] b9 c3 [2] ae c8 [2] b5 86 [2] 88 }

  condition:
    any of them
}