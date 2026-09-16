rule TTP_XOR_MULT_DOSStub_14ff {
  strings:
    $key_14ff = { 40 97 [2] 34 8f [2] 73 8d [2] 34 9c [2] 7a 90 [2] 76 9a [2] 61 91 [2] 7a df [2] 47 }

  condition:
    any of them
}