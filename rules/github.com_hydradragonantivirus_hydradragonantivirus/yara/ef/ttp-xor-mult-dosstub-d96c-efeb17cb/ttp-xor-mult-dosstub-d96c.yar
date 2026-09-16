rule TTP_XOR_MULT_DOSStub_d96c {
  strings:
    $key_d96c = { 8d 04 [2] f9 1c [2] be 1e [2] f9 0f [2] b7 03 [2] bb 09 [2] ac 02 [2] b7 4c [2] 8a }

  condition:
    any of them
}