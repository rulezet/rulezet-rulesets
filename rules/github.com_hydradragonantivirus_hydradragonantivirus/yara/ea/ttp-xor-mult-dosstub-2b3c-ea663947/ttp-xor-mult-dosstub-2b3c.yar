rule TTP_XOR_MULT_DOSStub_2b3c {
  strings:
    $key_2b3c = { 7f 54 [2] 0b 4c [2] 4c 4e [2] 0b 5f [2] 45 53 [2] 49 59 [2] 5e 52 [2] 45 1c [2] 78 }

  condition:
    any of them
}