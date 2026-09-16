rule TTP_XOR_MULT_DOSStub_296d {
  strings:
    $key_296d = { 7d 05 [2] 09 1d [2] 4e 1f [2] 09 0e [2] 47 02 [2] 4b 08 [2] 5c 03 [2] 47 4d [2] 7a }

  condition:
    any of them
}