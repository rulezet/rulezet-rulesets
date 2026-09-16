rule TTP_XOR_MULT_DOSStub_906a {
  strings:
    $key_906a = { c4 02 [2] b0 1a [2] f7 18 [2] b0 09 [2] fe 05 [2] f2 0f [2] e5 04 [2] fe 4a [2] c3 }

  condition:
    any of them
}