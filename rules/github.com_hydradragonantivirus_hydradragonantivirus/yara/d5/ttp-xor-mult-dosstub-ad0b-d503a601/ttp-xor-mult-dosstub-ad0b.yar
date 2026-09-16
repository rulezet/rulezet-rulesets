rule TTP_XOR_MULT_DOSStub_ad0b {
  strings:
    $key_ad0b = { f9 63 [2] 8d 7b [2] ca 79 [2] 8d 68 [2] c3 64 [2] cf 6e [2] d8 65 [2] c3 2b [2] fe }

  condition:
    any of them
}