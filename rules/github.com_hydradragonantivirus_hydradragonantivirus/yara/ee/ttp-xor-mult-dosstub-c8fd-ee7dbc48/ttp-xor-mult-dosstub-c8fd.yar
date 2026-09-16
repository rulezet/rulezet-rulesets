rule TTP_XOR_MULT_DOSStub_c8fd {
  strings:
    $key_c8fd = { 9c 95 [2] e8 8d [2] af 8f [2] e8 9e [2] a6 92 [2] aa 98 [2] bd 93 [2] a6 dd [2] 9b }

  condition:
    any of them
}