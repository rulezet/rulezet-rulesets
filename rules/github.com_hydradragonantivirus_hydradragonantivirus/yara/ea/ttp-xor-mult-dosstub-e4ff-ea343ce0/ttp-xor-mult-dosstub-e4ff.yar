rule TTP_XOR_MULT_DOSStub_e4ff {
  strings:
    $key_e4ff = { b0 97 [2] c4 8f [2] 83 8d [2] c4 9c [2] 8a 90 [2] 86 9a [2] 91 91 [2] 8a df [2] b7 }

  condition:
    any of them
}