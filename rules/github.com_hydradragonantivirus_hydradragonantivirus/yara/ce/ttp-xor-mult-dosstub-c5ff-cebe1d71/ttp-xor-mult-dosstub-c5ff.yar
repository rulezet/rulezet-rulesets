rule TTP_XOR_MULT_DOSStub_c5ff {
  strings:
    $key_c5ff = { 91 97 [2] e5 8f [2] a2 8d [2] e5 9c [2] ab 90 [2] a7 9a [2] b0 91 [2] ab df [2] 96 }

  condition:
    any of them
}