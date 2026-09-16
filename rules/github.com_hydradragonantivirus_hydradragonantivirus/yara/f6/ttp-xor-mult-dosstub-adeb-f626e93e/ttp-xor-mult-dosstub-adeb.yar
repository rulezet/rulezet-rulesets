rule TTP_XOR_MULT_DOSStub_adeb {
  strings:
    $key_adeb = { f9 83 [2] 8d 9b [2] ca 99 [2] 8d 88 [2] c3 84 [2] cf 8e [2] d8 85 [2] c3 cb [2] fe }

  condition:
    any of them
}