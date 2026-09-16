rule TTP_XOR_MULT_DOSStub_9aae {
  strings:
    $key_9aae = { ce c6 [2] ba de [2] fd dc [2] ba cd [2] f4 c1 [2] f8 cb [2] ef c0 [2] f4 8e [2] c9 }

  condition:
    any of them
}