rule TTP_XOR_MULT_DOSStub_a85f {
  strings:
    $key_a85f = { fc 37 [2] 88 2f [2] cf 2d [2] 88 3c [2] c6 30 [2] ca 3a [2] dd 31 [2] c6 7f [2] fb }

  condition:
    any of them
}