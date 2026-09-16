rule TTP_XOR_QUAD_CurrentVersionRun_e26e {
  strings:
    $key_e26e = { b1 01 [2] 95 0f [2] be 23 [2] 90 01 [2] 84 1a [2] 8b 00 [2] 95 1d [2] 97 1c [2] 8c 1a [2] 90 1d [2] 8c 32 }

  condition:
    any of them
}