rule TTP_XOR_MULT_DOSStub_fcff {
  strings:
    $key_fcff = { a8 97 [2] dc 8f [2] 9b 8d [2] dc 9c [2] 92 90 [2] 9e 9a [2] 89 91 [2] 92 df [2] af }

  condition:
    any of them
}