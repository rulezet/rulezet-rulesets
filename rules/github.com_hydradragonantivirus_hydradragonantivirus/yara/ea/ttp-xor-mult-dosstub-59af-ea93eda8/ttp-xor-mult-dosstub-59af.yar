rule TTP_XOR_MULT_DOSStub_59af {
  strings:
    $key_59af = { 0d c7 [2] 79 df [2] 3e dd [2] 79 cc [2] 37 c0 [2] 3b ca [2] 2c c1 [2] 37 8f [2] 0a }

  condition:
    any of them
}