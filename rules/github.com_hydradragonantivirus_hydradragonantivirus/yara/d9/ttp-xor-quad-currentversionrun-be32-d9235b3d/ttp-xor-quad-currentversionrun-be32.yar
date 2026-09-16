rule TTP_XOR_QUAD_CurrentVersionRun_be32 {
  strings:
    $key_be32 = { ed 5d [2] c9 53 [2] e2 7f [2] cc 5d [2] d8 46 [2] d7 5c [2] c9 41 [2] cb 40 [2] d0 46 [2] cc 41 [2] d0 6e }

  condition:
    any of them
}