rule TTP_XOR_QUAD_CurrentVersionRun_e219 {
  strings:
    $key_e219 = { b1 76 [2] 95 78 [2] be 54 [2] 90 76 [2] 84 6d [2] 8b 77 [2] 95 6a [2] 97 6b [2] 8c 6d [2] 90 6a [2] 8c 45 }

  condition:
    any of them
}