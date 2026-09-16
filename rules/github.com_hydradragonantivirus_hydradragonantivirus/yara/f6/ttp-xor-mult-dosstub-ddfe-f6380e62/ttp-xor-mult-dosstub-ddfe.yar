rule TTP_XOR_MULT_DOSStub_ddfe {
  strings:
    $key_ddfe = { 89 96 [2] fd 8e [2] ba 8c [2] fd 9d [2] b3 91 [2] bf 9b [2] a8 90 [2] b3 de [2] 8e }

  condition:
    any of them
}