rule TTP_XOR_MULT_DOSStub_0fff {
  strings:
    $key_0fff = { 5b 97 [2] 2f 8f [2] 68 8d [2] 2f 9c [2] 61 90 [2] 6d 9a [2] 7a 91 [2] 61 df [2] 5c }

  condition:
    any of them
}