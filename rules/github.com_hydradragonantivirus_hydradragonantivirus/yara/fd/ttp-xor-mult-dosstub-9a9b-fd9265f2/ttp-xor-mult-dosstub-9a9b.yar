rule TTP_XOR_MULT_DOSStub_9a9b {
  strings:
    $key_9a9b = { ce f3 [2] ba eb [2] fd e9 [2] ba f8 [2] f4 f4 [2] f8 fe [2] ef f5 [2] f4 bb [2] c9 }

  condition:
    any of them
}