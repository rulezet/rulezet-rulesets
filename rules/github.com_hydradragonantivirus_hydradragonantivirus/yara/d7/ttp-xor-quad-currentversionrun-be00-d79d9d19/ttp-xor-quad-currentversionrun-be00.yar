rule TTP_XOR_QUAD_CurrentVersionRun_be00 {
  strings:
    $key_be00 = { ed 6f [2] c9 61 [2] e2 4d [2] cc 6f [2] d8 74 [2] d7 6e [2] c9 73 [2] cb 72 [2] d0 74 [2] cc 73 [2] d0 5c }

  condition:
    any of them
}