rule TTP_XOR_QUAD_CurrentVersionRun_be3f {
  strings:
    $key_be3f = { ed 50 [2] c9 5e [2] e2 72 [2] cc 50 [2] d8 4b [2] d7 51 [2] c9 4c [2] cb 4d [2] d0 4b [2] cc 4c [2] d0 63 }

  condition:
    any of them
}