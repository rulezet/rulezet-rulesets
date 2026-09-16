rule TTP_XOR_MULT_DOSStub_bf8c {
  strings:
    $key_bf8c = { eb e4 [2] 9f fc [2] d8 fe [2] 9f ef [2] d1 e3 [2] dd e9 [2] ca e2 [2] d1 ac [2] ec }

  condition:
    any of them
}