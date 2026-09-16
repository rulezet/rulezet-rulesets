rule TTP_XOR_MULT_DOSStub_31fe {
  strings:
    $key_31fe = { 65 96 [2] 11 8e [2] 56 8c [2] 11 9d [2] 5f 91 [2] 53 9b [2] 44 90 [2] 5f de [2] 62 }

  condition:
    any of them
}