rule TTP_XOR_MULT_DOSStub_6fff {
  strings:
    $key_6fff = { 3b 97 [2] 4f 8f [2] 08 8d [2] 4f 9c [2] 01 90 [2] 0d 9a [2] 1a 91 [2] 01 df [2] 3c }

  condition:
    any of them
}