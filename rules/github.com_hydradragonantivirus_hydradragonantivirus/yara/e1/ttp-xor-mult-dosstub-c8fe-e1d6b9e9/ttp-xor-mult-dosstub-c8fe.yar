rule TTP_XOR_MULT_DOSStub_c8fe {
  strings:
    $key_c8fe = { 9c 96 [2] e8 8e [2] af 8c [2] e8 9d [2] a6 91 [2] aa 9b [2] bd 90 [2] a6 de [2] 9b }

  condition:
    any of them
}