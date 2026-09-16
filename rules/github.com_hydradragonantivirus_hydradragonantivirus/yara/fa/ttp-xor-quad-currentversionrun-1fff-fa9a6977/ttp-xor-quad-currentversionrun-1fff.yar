rule TTP_XOR_QUAD_CurrentVersionRun_1fff {
  strings:
    $key_1fff = { 4c 90 [2] 68 9e [2] 43 b2 [2] 6d 90 [2] 79 8b [2] 76 91 [2] 68 8c [2] 6a 8d [2] 71 8b [2] 6d 8c [2] 71 a3 }

  condition:
    any of them
}