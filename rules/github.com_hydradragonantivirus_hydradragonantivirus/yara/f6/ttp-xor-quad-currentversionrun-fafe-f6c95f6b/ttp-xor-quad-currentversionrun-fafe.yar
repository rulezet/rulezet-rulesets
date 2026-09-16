rule TTP_XOR_QUAD_CurrentVersionRun_fafe {
  strings:
    $key_fafe = { a9 91 [2] 8d 9f [2] a6 b3 [2] 88 91 [2] 9c 8a [2] 93 90 [2] 8d 8d [2] 8f 8c [2] 94 8a [2] 88 8d [2] 94 a2 }

  condition:
    any of them
}