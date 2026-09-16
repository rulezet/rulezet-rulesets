rule TTP_XOR_MULT_DOSStub_88b8 {
  strings:
    $key_88b8 = { dc d0 [2] a8 c8 [2] ef ca [2] a8 db [2] e6 d7 [2] ea dd [2] fd d6 [2] e6 98 [2] db }

  condition:
    any of them
}