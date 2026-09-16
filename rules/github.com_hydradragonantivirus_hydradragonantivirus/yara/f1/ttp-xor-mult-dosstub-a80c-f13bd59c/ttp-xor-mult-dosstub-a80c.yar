rule TTP_XOR_MULT_DOSStub_a80c {
  strings:
    $key_a80c = { fc 64 [2] 88 7c [2] cf 7e [2] 88 6f [2] c6 63 [2] ca 69 [2] dd 62 [2] c6 2c [2] fb }

  condition:
    any of them
}