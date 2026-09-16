rule TTP_XOR_MULT_DOSStub_36fe {
  strings:
    $key_36fe = { 62 96 [2] 16 8e [2] 51 8c [2] 16 9d [2] 58 91 [2] 54 9b [2] 43 90 [2] 58 de [2] 65 }

  condition:
    any of them
}