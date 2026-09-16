rule TTP_XOR_MULT_DOSStub_d92f {
  strings:
    $key_d92f = { 8d 47 [2] f9 5f [2] be 5d [2] f9 4c [2] b7 40 [2] bb 4a [2] ac 41 [2] b7 0f [2] 8a }

  condition:
    any of them
}