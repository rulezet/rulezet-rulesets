rule TTP_XOR_MULT_DOSStub_8bbd {
  strings:
    $key_8bbd = { df d5 [2] ab cd [2] ec cf [2] ab de [2] e5 d2 [2] e9 d8 [2] fe d3 [2] e5 9d [2] d8 }

  condition:
    any of them
}