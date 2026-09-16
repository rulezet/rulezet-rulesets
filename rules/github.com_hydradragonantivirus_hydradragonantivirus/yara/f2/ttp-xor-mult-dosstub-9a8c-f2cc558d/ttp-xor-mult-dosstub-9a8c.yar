rule TTP_XOR_MULT_DOSStub_9a8c {
  strings:
    $key_9a8c = { ce e4 [2] ba fc [2] fd fe [2] ba ef [2] f4 e3 [2] f8 e9 [2] ef e2 [2] f4 ac [2] c9 }

  condition:
    any of them
}