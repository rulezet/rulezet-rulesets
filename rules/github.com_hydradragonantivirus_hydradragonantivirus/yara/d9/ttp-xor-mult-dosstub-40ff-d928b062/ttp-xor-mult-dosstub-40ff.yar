rule TTP_XOR_MULT_DOSStub_40ff {
  strings:
    $key_40ff = { 14 97 [2] 60 8f [2] 27 8d [2] 60 9c [2] 2e 90 [2] 22 9a [2] 35 91 [2] 2e df [2] 13 }

  condition:
    any of them
}