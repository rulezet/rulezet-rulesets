rule TTP_XOR_QUAD_CurrentVersionRun_3bfe {
  strings:
    $key_3bfe = { 68 91 [2] 4c 9f [2] 67 b3 [2] 49 91 [2] 5d 8a [2] 52 90 [2] 4c 8d [2] 4e 8c [2] 55 8a [2] 49 8d [2] 55 a2 }

  condition:
    any of them
}