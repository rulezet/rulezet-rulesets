rule TTP_XOR_MULT_DOSStub_dbed {
  strings:
    $key_dbed = { 8f 85 [2] fb 9d [2] bc 9f [2] fb 8e [2] b5 82 [2] b9 88 [2] ae 83 [2] b5 cd [2] 88 }

  condition:
    any of them
}