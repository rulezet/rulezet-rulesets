rule TTP_XOR_MULT_DOSStub_d93a {
  strings:
    $key_d93a = { 8d 52 [2] f9 4a [2] be 48 [2] f9 59 [2] b7 55 [2] bb 5f [2] ac 54 [2] b7 1a [2] 8a }

  condition:
    any of them
}