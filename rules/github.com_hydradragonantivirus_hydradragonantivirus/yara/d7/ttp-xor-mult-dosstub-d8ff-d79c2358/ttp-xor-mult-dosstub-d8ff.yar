rule TTP_XOR_MULT_DOSStub_d8ff {
  strings:
    $key_d8ff = { 8c 97 [2] f8 8f [2] bf 8d [2] f8 9c [2] b6 90 [2] ba 9a [2] ad 91 [2] b6 df [2] 8b }

  condition:
    any of them
}