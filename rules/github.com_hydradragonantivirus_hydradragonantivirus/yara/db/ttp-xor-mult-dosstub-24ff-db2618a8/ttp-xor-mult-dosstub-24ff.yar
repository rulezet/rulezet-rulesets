rule TTP_XOR_MULT_DOSStub_24ff {
  strings:
    $key_24ff = { 70 97 [2] 04 8f [2] 43 8d [2] 04 9c [2] 4a 90 [2] 46 9a [2] 51 91 [2] 4a df [2] 77 }

  condition:
    any of them
}