rule TTP_XOR_MULT_DOSStub_9aff {
  strings:
    $key_9aff = { ce 97 [2] ba 8f [2] fd 8d [2] ba 9c [2] f4 90 [2] f8 9a [2] ef 91 [2] f4 df [2] c9 }

  condition:
    any of them
}