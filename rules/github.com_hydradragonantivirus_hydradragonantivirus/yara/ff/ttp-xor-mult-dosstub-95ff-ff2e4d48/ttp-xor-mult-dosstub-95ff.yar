rule TTP_XOR_MULT_DOSStub_95ff {
  strings:
    $key_95ff = { c1 97 [2] b5 8f [2] f2 8d [2] b5 9c [2] fb 90 [2] f7 9a [2] e0 91 [2] fb df [2] c6 }

  condition:
    any of them
}