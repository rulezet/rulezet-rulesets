rule TTP_XOR_MULT_DOSStub_cffe {
  strings:
    $key_cffe = { 9b 96 [2] ef 8e [2] a8 8c [2] ef 9d [2] a1 91 [2] ad 9b [2] ba 90 [2] a1 de [2] 9c }

  condition:
    any of them
}