rule TTP_XOR_MULT_DOSStub_8bbf {
  strings:
    $key_8bbf = { df d7 [2] ab cf [2] ec cd [2] ab dc [2] e5 d0 [2] e9 da [2] fe d1 [2] e5 9f [2] d8 }

  condition:
    any of them
}