rule TTP_XOR_MULT_DOSStub_bbed {
  strings:
    $key_bbed = { ef 85 [2] 9b 9d [2] dc 9f [2] 9b 8e [2] d5 82 [2] d9 88 [2] ce 83 [2] d5 cd [2] e8 }

  condition:
    any of them
}