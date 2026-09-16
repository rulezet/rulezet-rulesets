rule TTP_XOR_MULT_DOSStub_17fd {
  strings:
    $key_17fd = { 43 95 [2] 37 8d [2] 70 8f [2] 37 9e [2] 79 92 [2] 75 98 [2] 62 93 [2] 79 dd [2] 44 }

  condition:
    any of them
}