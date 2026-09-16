rule TTP_XOR_QUAD_CurrentVersionRun_beef {
  strings:
    $key_beef = { ed 80 [2] c9 8e [2] e2 a2 [2] cc 80 [2] d8 9b [2] d7 81 [2] c9 9c [2] cb 9d [2] d0 9b [2] cc 9c [2] d0 b3 }

  condition:
    any of them
}