rule TTP_XOR_MULT_DOSStub_79af {
  strings:
    $key_79af = { 2d c7 [2] 59 df [2] 1e dd [2] 59 cc [2] 17 c0 [2] 1b ca [2] 0c c1 [2] 17 8f [2] 2a }

  condition:
    any of them
}