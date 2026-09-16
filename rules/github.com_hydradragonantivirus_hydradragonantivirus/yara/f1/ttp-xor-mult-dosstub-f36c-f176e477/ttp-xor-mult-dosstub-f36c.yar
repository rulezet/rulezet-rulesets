rule TTP_XOR_MULT_DOSStub_f36c {
  strings:
    $key_f36c = { a7 04 [2] d3 1c [2] 94 1e [2] d3 0f [2] 9d 03 [2] 91 09 [2] 86 02 [2] 9d 4c [2] a0 }

  condition:
    any of them
}