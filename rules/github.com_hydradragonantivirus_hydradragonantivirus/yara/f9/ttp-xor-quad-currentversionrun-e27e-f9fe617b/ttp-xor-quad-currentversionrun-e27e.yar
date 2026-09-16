rule TTP_XOR_QUAD_CurrentVersionRun_e27e {
  strings:
    $key_e27e = { b1 11 [2] 95 1f [2] be 33 [2] 90 11 [2] 84 0a [2] 8b 10 [2] 95 0d [2] 97 0c [2] 8c 0a [2] 90 0d [2] 8c 22 }

  condition:
    any of them
}