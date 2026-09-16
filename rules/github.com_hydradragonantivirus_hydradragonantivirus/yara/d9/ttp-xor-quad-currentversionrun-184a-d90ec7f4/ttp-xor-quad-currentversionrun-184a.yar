rule TTP_XOR_QUAD_CurrentVersionRun_184a {
  strings:
    $key_184a = { 4b 25 [2] 6f 2b [2] 44 07 [2] 6a 25 [2] 7e 3e [2] 71 24 [2] 6f 39 [2] 6d 38 [2] 76 3e [2] 6a 39 [2] 76 16 }

  condition:
    any of them
}