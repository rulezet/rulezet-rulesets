rule TTP_XOR_QUAD_CurrentVersionRun_f8f9 {
  strings:
    $key_f8f9 = { ab 96 [2] 8f 98 [2] a4 b4 [2] 8a 96 [2] 9e 8d [2] 91 97 [2] 8f 8a [2] 8d 8b [2] 96 8d [2] 8a 8a [2] 96 a5 }

  condition:
    any of them
}