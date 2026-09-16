rule TTP_XOR_QUAD_CurrentVersionRun_ecfe {
  strings:
    $key_ecfe = { bf 91 [2] 9b 9f [2] b0 b3 [2] 9e 91 [2] 8a 8a [2] 85 90 [2] 9b 8d [2] 99 8c [2] 82 8a [2] 9e 8d [2] 82 a2 }

  condition:
    any of them
}