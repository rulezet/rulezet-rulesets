rule TTP_XOR_QUAD_CurrentVersionRun_e218 {
  strings:
    $key_e218 = { b1 77 [2] 95 79 [2] be 55 [2] 90 77 [2] 84 6c [2] 8b 76 [2] 95 6b [2] 97 6a [2] 8c 6c [2] 90 6b [2] 8c 44 }

  condition:
    any of them
}