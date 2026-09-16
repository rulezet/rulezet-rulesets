rule TTP_XOR_MULT_DOSStub_ab5e {
  strings:
    $key_ab5e = { ff 36 [2] 8b 2e [2] cc 2c [2] 8b 3d [2] c5 31 [2] c9 3b [2] de 30 [2] c5 7e [2] f8 }

  condition:
    any of them
}