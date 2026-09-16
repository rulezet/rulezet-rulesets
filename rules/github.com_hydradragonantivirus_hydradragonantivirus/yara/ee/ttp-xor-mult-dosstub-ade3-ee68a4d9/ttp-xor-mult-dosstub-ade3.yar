rule TTP_XOR_MULT_DOSStub_ade3 {
  strings:
    $key_ade3 = { f9 8b [2] 8d 93 [2] ca 91 [2] 8d 80 [2] c3 8c [2] cf 86 [2] d8 8d [2] c3 c3 [2] fe }

  condition:
    any of them
}