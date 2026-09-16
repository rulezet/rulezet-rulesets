rule TTP_XOR_MULT_DOSStub_f2fd {
  strings:
    $key_f2fd = { a6 95 [2] d2 8d [2] 95 8f [2] d2 9e [2] 9c 92 [2] 90 98 [2] 87 93 [2] 9c dd [2] a1 }

  condition:
    any of them
}