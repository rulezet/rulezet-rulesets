rule TTP_XOR_QUAD_CurrentVersionRun_e80e {
  strings:
    $key_e80e = { bb 61 [2] 9f 6f [2] b4 43 [2] 9a 61 [2] 8e 7a [2] 81 60 [2] 9f 7d [2] 9d 7c [2] 86 7a [2] 9a 7d [2] 86 52 }

  condition:
    any of them
}