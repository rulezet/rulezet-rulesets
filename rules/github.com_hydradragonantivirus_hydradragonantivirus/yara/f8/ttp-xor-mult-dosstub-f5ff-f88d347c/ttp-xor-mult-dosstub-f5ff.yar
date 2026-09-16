rule TTP_XOR_MULT_DOSStub_f5ff {
  strings:
    $key_f5ff = { a1 97 [2] d5 8f [2] 92 8d [2] d5 9c [2] 9b 90 [2] 97 9a [2] 80 91 [2] 9b df [2] a6 }

  condition:
    any of them
}