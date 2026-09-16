rule TTP_XOR_MULT_DOSStub_cafe {
  strings:
    $key_cafe = { 9e 96 [2] ea 8e [2] ad 8c [2] ea 9d [2] a4 91 [2] a8 9b [2] bf 90 [2] a4 de [2] 99 }

  condition:
    any of them
}