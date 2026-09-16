rule TTP_XOR_QUAD_CurrentVersionRun_f97c {
  strings:
    $key_f97c = { aa 13 [2] 8e 1d [2] a5 31 [2] 8b 13 [2] 9f 08 [2] 90 12 [2] 8e 0f [2] 8c 0e [2] 97 08 [2] 8b 0f [2] 97 20 }

  condition:
    any of them
}