rule TTP_XOR_QUAD_CurrentVersionRun_bee3 {
  strings:
    $key_bee3 = { ed 8c [2] c9 82 [2] e2 ae [2] cc 8c [2] d8 97 [2] d7 8d [2] c9 90 [2] cb 91 [2] d0 97 [2] cc 90 [2] d0 bf }

  condition:
    any of them
}