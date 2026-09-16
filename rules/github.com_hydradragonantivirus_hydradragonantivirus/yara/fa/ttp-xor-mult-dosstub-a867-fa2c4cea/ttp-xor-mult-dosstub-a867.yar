rule TTP_XOR_MULT_DOSStub_a867 {
  strings:
    $key_a867 = { fc 0f [2] 88 17 [2] cf 15 [2] 88 04 [2] c6 08 [2] ca 02 [2] dd 09 [2] c6 47 [2] fb }

  condition:
    any of them
}