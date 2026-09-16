rule TTP_XOR_MULT_DOSStub_bf9c {
  strings:
    $key_bf9c = { eb f4 [2] 9f ec [2] d8 ee [2] 9f ff [2] d1 f3 [2] dd f9 [2] ca f2 [2] d1 bc [2] ec }

  condition:
    any of them
}