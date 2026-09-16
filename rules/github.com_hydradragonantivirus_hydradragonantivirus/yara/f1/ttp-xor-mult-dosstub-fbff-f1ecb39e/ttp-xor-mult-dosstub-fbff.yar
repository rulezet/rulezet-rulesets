rule TTP_XOR_MULT_DOSStub_fbff {
  strings:
    $key_fbff = { af 97 [2] db 8f [2] 9c 8d [2] db 9c [2] 95 90 [2] 99 9a [2] 8e 91 [2] 95 df [2] a8 }

  condition:
    any of them
}