rule TTP_XOR_MULT_DOSStub_296c {
  strings:
    $key_296c = { 7d 04 [2] 09 1c [2] 4e 1e [2] 09 0f [2] 47 03 [2] 4b 09 [2] 5c 02 [2] 47 4c [2] 7a }

  condition:
    any of them
}