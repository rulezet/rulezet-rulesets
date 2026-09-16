rule TTP_XOR_MULT_DOSStub_a852 {
  strings:
    $key_a852 = { fc 3a [2] 88 22 [2] cf 20 [2] 88 31 [2] c6 3d [2] ca 37 [2] dd 3c [2] c6 72 [2] fb }

  condition:
    any of them
}