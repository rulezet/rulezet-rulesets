rule TTP_XOR_MULT_DOSStub_d4ff {
  strings:
    $key_d4ff = { 80 97 [2] f4 8f [2] b3 8d [2] f4 9c [2] ba 90 [2] b6 9a [2] a1 91 [2] ba df [2] 87 }

  condition:
    any of them
}