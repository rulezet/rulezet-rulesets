rule TTP_XOR_MULT_DOSStub_57ff {
  strings:
    $key_57ff = { 03 97 [2] 77 8f [2] 30 8d [2] 77 9c [2] 39 90 [2] 35 9a [2] 22 91 [2] 39 df [2] 04 }

  condition:
    any of them
}