rule TTP_XOR_QUAD_CurrentVersionRun_f92e {
  strings:
    $key_f92e = { aa 41 [2] 8e 4f [2] a5 63 [2] 8b 41 [2] 9f 5a [2] 90 40 [2] 8e 5d [2] 8c 5c [2] 97 5a [2] 8b 5d [2] 97 72 }

  condition:
    any of them
}