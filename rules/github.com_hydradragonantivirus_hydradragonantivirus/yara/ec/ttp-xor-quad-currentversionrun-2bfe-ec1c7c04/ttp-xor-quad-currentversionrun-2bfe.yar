rule TTP_XOR_QUAD_CurrentVersionRun_2bfe {
  strings:
    $key_2bfe = { 78 91 [2] 5c 9f [2] 77 b3 [2] 59 91 [2] 4d 8a [2] 42 90 [2] 5c 8d [2] 5e 8c [2] 45 8a [2] 59 8d [2] 45 a2 }

  condition:
    any of them
}