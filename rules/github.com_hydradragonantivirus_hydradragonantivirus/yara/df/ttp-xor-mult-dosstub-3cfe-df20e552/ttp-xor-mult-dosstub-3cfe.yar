rule TTP_XOR_MULT_DOSStub_3cfe {
  strings:
    $key_3cfe = { 68 96 [2] 1c 8e [2] 5b 8c [2] 1c 9d [2] 52 91 [2] 5e 9b [2] 49 90 [2] 52 de [2] 6f }

  condition:
    any of them
}