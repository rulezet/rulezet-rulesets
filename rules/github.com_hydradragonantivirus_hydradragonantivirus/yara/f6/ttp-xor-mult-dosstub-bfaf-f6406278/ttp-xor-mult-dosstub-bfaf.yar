rule TTP_XOR_MULT_DOSStub_bfaf {
  strings:
    $key_bfaf = { eb c7 [2] 9f df [2] d8 dd [2] 9f cc [2] d1 c0 [2] dd ca [2] ca c1 [2] d1 8f [2] ec }

  condition:
    any of them
}