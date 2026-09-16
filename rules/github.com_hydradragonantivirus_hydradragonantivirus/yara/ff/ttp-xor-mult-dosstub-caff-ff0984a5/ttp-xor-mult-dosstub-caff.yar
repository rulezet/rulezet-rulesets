rule TTP_XOR_MULT_DOSStub_caff {
  strings:
    $key_caff = { 9e 97 [2] ea 8f [2] ad 8d [2] ea 9c [2] a4 90 [2] a8 9a [2] bf 91 [2] a4 df [2] 99 }

  condition:
    any of them
}