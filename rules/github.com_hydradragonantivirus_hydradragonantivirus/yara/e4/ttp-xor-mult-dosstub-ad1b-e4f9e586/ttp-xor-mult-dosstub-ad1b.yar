rule TTP_XOR_MULT_DOSStub_ad1b {
  strings:
    $key_ad1b = { f9 73 [2] 8d 6b [2] ca 69 [2] 8d 78 [2] c3 74 [2] cf 7e [2] d8 75 [2] c3 3b [2] fe }

  condition:
    any of them
}