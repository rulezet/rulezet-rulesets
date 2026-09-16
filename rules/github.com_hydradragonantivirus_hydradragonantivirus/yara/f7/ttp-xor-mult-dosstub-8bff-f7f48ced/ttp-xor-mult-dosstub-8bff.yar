rule TTP_XOR_MULT_DOSStub_8bff {
  strings:
    $key_8bff = { df 97 [2] ab 8f [2] ec 8d [2] ab 9c [2] e5 90 [2] e9 9a [2] fe 91 [2] e5 df [2] d8 }

  condition:
    any of them
}