rule TTP_XOR_MULT_DOSStub_abff {
  strings:
    $key_abff = { ff 97 [2] 8b 8f [2] cc 8d [2] 8b 9c [2] c5 90 [2] c9 9a [2] de 91 [2] c5 df [2] f8 }

  condition:
    any of them
}