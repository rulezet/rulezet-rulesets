rule TTP_XOR_QUAD_CurrentVersionRun_1ffe {
  strings:
    $key_1ffe = { 4c 91 [2] 68 9f [2] 43 b3 [2] 6d 91 [2] 79 8a [2] 76 90 [2] 68 8d [2] 6a 8c [2] 71 8a [2] 6d 8d [2] 71 a2 }

  condition:
    any of them
}