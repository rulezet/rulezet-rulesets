rule TTP_XOR_MULT_DOSStub_11ff {
  strings:
    $key_11ff = { 45 97 [2] 31 8f [2] 76 8d [2] 31 9c [2] 7f 90 [2] 73 9a [2] 64 91 [2] 7f df [2] 42 }

  condition:
    any of them
}