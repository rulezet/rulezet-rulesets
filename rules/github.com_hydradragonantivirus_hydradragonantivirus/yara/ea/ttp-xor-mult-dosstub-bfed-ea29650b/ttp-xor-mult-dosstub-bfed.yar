rule TTP_XOR_MULT_DOSStub_bfed {
  strings:
    $key_bfed = { eb 85 [2] 9f 9d [2] d8 9f [2] 9f 8e [2] d1 82 [2] dd 88 [2] ca 83 [2] d1 cd [2] ec }

  condition:
    any of them
}