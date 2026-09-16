rule TTP_XOR_MULT_DOSStub_deeb {
  strings:
    $key_deeb = { 8a 83 [2] fe 9b [2] b9 99 [2] fe 88 [2] b0 84 [2] bc 8e [2] ab 85 [2] b0 cb [2] 8d }

  condition:
    any of them
}