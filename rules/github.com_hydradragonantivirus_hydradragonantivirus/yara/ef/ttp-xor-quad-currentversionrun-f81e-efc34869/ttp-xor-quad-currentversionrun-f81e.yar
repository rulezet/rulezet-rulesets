rule TTP_XOR_QUAD_CurrentVersionRun_f81e {
  strings:
    $key_f81e = { ab 71 [2] 8f 7f [2] a4 53 [2] 8a 71 [2] 9e 6a [2] 91 70 [2] 8f 6d [2] 8d 6c [2] 96 6a [2] 8a 6d [2] 96 42 }

  condition:
    any of them
}