rule TTP_XOR_MULT_DOSStub_3fff {
  strings:
    $key_3fff = { 6b 97 [2] 1f 8f [2] 58 8d [2] 1f 9c [2] 51 90 [2] 5d 9a [2] 4a 91 [2] 51 df [2] 6c }

  condition:
    any of them
}