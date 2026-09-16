rule TTP_XOR_MULT_DOSStub_e2ff {
  strings:
    $key_e2ff = { b6 97 [2] c2 8f [2] 85 8d [2] c2 9c [2] 8c 90 [2] 80 9a [2] 97 91 [2] 8c df [2] b1 }

  condition:
    any of them
}