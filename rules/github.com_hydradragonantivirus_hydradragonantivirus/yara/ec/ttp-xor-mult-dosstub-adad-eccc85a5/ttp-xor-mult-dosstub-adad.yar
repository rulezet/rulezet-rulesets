rule TTP_XOR_MULT_DOSStub_adad {
  strings:
    $key_adad = { f9 c5 [2] 8d dd [2] ca df [2] 8d ce [2] c3 c2 [2] cf c8 [2] d8 c3 [2] c3 8d [2] fe }

  condition:
    any of them
}