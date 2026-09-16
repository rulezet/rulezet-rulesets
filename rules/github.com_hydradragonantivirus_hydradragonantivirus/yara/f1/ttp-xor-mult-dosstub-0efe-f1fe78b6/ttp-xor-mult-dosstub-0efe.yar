rule TTP_XOR_MULT_DOSStub_0efe {
  strings:
    $key_0efe = { 5a 96 [2] 2e 8e [2] 69 8c [2] 2e 9d [2] 60 91 [2] 6c 9b [2] 7b 90 [2] 60 de [2] 5d }

  condition:
    any of them
}