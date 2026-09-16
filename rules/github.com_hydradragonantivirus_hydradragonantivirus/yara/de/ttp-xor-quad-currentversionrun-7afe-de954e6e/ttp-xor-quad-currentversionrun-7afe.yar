rule TTP_XOR_QUAD_CurrentVersionRun_7afe {
  strings:
    $key_7afe = { 29 91 [2] 0d 9f [2] 26 b3 [2] 08 91 [2] 1c 8a [2] 13 90 [2] 0d 8d [2] 0f 8c [2] 14 8a [2] 08 8d [2] 14 a2 }

  condition:
    any of them
}