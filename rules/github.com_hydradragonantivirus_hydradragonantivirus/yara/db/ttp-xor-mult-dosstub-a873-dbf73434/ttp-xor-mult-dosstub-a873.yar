rule TTP_XOR_MULT_DOSStub_a873 {
  strings:
    $key_a873 = { fc 1b [2] 88 03 [2] cf 01 [2] 88 10 [2] c6 1c [2] ca 16 [2] dd 1d [2] c6 53 [2] fb }

  condition:
    any of them
}