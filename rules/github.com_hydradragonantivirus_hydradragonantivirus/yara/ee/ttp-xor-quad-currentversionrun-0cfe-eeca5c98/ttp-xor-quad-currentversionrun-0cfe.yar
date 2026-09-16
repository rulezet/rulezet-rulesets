rule TTP_XOR_QUAD_CurrentVersionRun_0cfe {
  strings:
    $key_0cfe = { 5f 91 [2] 7b 9f [2] 50 b3 [2] 7e 91 [2] 6a 8a [2] 65 90 [2] 7b 8d [2] 79 8c [2] 62 8a [2] 7e 8d [2] 62 a2 }

  condition:
    any of them
}