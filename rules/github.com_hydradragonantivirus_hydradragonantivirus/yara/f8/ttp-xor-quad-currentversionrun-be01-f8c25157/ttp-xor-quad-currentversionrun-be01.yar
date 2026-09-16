rule TTP_XOR_QUAD_CurrentVersionRun_be01 {
  strings:
    $key_be01 = { ed 6e [2] c9 60 [2] e2 4c [2] cc 6e [2] d8 75 [2] d7 6f [2] c9 72 [2] cb 73 [2] d0 75 [2] cc 72 [2] d0 5d }

  condition:
    any of them
}