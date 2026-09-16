rule TTP_XOR_MULT_DOSStub_bf95 {
  strings:
    $key_bf95 = { eb fd [2] 9f e5 [2] d8 e7 [2] 9f f6 [2] d1 fa [2] dd f0 [2] ca fb [2] d1 b5 [2] ec }

  condition:
    any of them
}