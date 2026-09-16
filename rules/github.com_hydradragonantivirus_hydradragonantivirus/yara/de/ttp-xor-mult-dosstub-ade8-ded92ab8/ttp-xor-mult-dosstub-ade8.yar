rule TTP_XOR_MULT_DOSStub_ade8 {
  strings:
    $key_ade8 = { f9 80 [2] 8d 98 [2] ca 9a [2] 8d 8b [2] c3 87 [2] cf 8d [2] d8 86 [2] c3 c8 [2] fe }

  condition:
    any of them
}