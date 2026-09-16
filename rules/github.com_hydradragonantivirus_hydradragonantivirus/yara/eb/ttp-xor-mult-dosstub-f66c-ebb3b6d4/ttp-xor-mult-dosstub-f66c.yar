rule TTP_XOR_MULT_DOSStub_f66c {
  strings:
    $key_f66c = { a2 04 [2] d6 1c [2] 91 1e [2] d6 0f [2] 98 03 [2] 94 09 [2] 83 02 [2] 98 4c [2] a5 }

  condition:
    any of them
}