rule TTP_XOR_QUAD_CurrentVersionRun_befe {
  strings:
    $key_befe = { ed 91 [2] c9 9f [2] e2 b3 [2] cc 91 [2] d8 8a [2] d7 90 [2] c9 8d [2] cb 8c [2] d0 8a [2] cc 8d [2] d0 a2 }

  condition:
    any of them
}