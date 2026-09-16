rule TTP_XOR_MULT_DOSStub_f3ff {
  strings:
    $key_f3ff = { a7 97 [2] d3 8f [2] 94 8d [2] d3 9c [2] 9d 90 [2] 91 9a [2] 86 91 [2] 9d df [2] a0 }

  condition:
    any of them
}