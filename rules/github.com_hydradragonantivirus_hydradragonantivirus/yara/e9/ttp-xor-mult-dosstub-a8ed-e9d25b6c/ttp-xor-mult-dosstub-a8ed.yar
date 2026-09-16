rule TTP_XOR_MULT_DOSStub_a8ed {
  strings:
    $key_a8ed = { fc 85 [2] 88 9d [2] cf 9f [2] 88 8e [2] c6 82 [2] ca 88 [2] dd 83 [2] c6 cd [2] fb }

  condition:
    any of them
}