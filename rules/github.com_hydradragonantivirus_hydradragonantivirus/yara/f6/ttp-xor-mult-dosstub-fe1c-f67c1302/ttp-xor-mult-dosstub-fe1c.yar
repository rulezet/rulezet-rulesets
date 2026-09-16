rule TTP_XOR_MULT_DOSStub_fe1c {
  strings:
    $key_fe1c = { aa 74 [2] de 6c [2] 99 6e [2] de 7f [2] 90 73 [2] 9c 79 [2] 8b 72 [2] 90 3c [2] ad }

  condition:
    any of them
}