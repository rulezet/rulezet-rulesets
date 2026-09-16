rule TTP_XOR_QUAD_CurrentVersionRun_f96a {
  strings:
    $key_f96a = { aa 05 [2] 8e 0b [2] a5 27 [2] 8b 05 [2] 9f 1e [2] 90 04 [2] 8e 19 [2] 8c 18 [2] 97 1e [2] 8b 19 [2] 97 36 }

  condition:
    any of them
}