rule TTP_XOR_MULT_DOSStub_8bfd {
  strings:
    $key_8bfd = { df 95 [2] ab 8d [2] ec 8f [2] ab 9e [2] e5 92 [2] e9 98 [2] fe 93 [2] e5 dd [2] d8 }

  condition:
    any of them
}