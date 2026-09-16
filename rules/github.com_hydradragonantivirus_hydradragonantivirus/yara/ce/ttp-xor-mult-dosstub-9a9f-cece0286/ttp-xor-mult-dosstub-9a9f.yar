rule TTP_XOR_MULT_DOSStub_9a9f {
  strings:
    $key_9a9f = { ce f7 [2] ba ef [2] fd ed [2] ba fc [2] f4 f0 [2] f8 fa [2] ef f1 [2] f4 bf [2] c9 }

  condition:
    any of them
}