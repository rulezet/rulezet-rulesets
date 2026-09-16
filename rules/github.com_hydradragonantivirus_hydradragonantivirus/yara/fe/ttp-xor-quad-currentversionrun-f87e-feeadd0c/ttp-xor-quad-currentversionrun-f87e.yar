rule TTP_XOR_QUAD_CurrentVersionRun_f87e {
  strings:
    $key_f87e = { ab 11 [2] 8f 1f [2] a4 33 [2] 8a 11 [2] 9e 0a [2] 91 10 [2] 8f 0d [2] 8d 0c [2] 96 0a [2] 8a 0d [2] 96 22 }

  condition:
    any of them
}