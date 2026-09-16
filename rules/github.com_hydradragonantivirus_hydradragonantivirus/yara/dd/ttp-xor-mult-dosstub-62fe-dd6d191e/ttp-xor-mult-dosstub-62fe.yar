rule TTP_XOR_MULT_DOSStub_62fe {
  strings:
    $key_62fe = { 36 96 [2] 42 8e [2] 05 8c [2] 42 9d [2] 0c 91 [2] 00 9b [2] 17 90 [2] 0c de [2] 31 }

  condition:
    any of them
}