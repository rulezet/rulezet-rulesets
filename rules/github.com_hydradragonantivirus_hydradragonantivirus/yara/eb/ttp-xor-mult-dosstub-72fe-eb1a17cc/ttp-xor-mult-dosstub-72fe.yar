rule TTP_XOR_MULT_DOSStub_72fe {
  strings:
    $key_72fe = { 26 96 [2] 52 8e [2] 15 8c [2] 52 9d [2] 1c 91 [2] 10 9b [2] 07 90 [2] 1c de [2] 21 }

  condition:
    any of them
}