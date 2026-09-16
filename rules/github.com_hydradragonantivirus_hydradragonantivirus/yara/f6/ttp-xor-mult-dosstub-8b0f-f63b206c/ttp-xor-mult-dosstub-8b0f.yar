rule TTP_XOR_MULT_DOSStub_8b0f {
  strings:
    $key_8b0f = { df 67 [2] ab 7f [2] ec 7d [2] ab 6c [2] e5 60 [2] e9 6a [2] fe 61 [2] e5 2f [2] d8 }

  condition:
    any of them
}