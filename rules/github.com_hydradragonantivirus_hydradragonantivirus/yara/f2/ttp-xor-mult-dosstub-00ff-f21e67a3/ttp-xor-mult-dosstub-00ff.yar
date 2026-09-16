rule TTP_XOR_MULT_DOSStub_00ff {
  strings:
    $key_00ff = { 54 97 [2] 20 8f [2] 67 8d [2] 20 9c [2] 6e 90 [2] 62 9a [2] 75 91 [2] 6e df [2] 53 }

  condition:
    any of them
}