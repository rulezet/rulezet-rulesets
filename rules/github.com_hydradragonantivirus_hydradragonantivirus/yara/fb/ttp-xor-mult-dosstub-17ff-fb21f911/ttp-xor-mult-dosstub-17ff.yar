rule TTP_XOR_MULT_DOSStub_17ff {
  strings:
    $key_17ff = { 43 97 [2] 37 8f [2] 70 8d [2] 37 9c [2] 79 90 [2] 75 9a [2] 62 91 [2] 79 df [2] 44 }

  condition:
    any of them
}