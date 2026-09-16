rule TTP_XOR_MULT_DOSStub_a86c {
  strings:
    $key_a86c = { fc 04 [2] 88 1c [2] cf 1e [2] 88 0f [2] c6 03 [2] ca 09 [2] dd 02 [2] c6 4c [2] fb }

  condition:
    any of them
}