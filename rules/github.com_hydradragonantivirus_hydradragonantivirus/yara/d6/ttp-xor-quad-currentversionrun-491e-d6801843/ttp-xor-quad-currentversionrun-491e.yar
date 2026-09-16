rule TTP_XOR_QUAD_CurrentVersionRun_491e {
  strings:
    $key_491e = { 1a 71 [2] 3e 7f [2] 15 53 [2] 3b 71 [2] 2f 6a [2] 20 70 [2] 3e 6d [2] 3c 6c [2] 27 6a [2] 3b 6d [2] 27 42 }

  condition:
    any of them
}