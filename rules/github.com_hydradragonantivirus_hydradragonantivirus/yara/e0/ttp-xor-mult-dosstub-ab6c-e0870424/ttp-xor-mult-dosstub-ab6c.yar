rule TTP_XOR_MULT_DOSStub_ab6c {
  strings:
    $key_ab6c = { ff 04 [2] 8b 1c [2] cc 1e [2] 8b 0f [2] c5 03 [2] c9 09 [2] de 02 [2] c5 4c [2] f8 }

  condition:
    any of them
}