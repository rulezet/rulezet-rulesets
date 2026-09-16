rule TTP_XOR_MULT_DOSStub_51fe {
  strings:
    $key_51fe = { 05 96 [2] 71 8e [2] 36 8c [2] 71 9d [2] 3f 91 [2] 33 9b [2] 24 90 [2] 3f de [2] 02 }

  condition:
    any of them
}