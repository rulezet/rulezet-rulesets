rule TTP_XOR_MULT_DOSStub_51ff {
  strings:
    $key_51ff = { 05 97 [2] 71 8f [2] 36 8d [2] 71 9c [2] 3f 90 [2] 33 9a [2] 24 91 [2] 3f df [2] 02 }

  condition:
    any of them
}