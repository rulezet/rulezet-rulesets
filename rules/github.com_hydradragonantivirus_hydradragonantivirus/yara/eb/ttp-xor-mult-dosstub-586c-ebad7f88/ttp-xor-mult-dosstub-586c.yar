rule TTP_XOR_MULT_DOSStub_586c {
  strings:
    $key_586c = { 0c 04 [2] 78 1c [2] 3f 1e [2] 78 0f [2] 36 03 [2] 3a 09 [2] 2d 02 [2] 36 4c [2] 0b }

  condition:
    any of them
}