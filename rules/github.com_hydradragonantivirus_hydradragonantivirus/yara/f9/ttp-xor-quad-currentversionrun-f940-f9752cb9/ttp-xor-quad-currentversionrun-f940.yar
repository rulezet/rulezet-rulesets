rule TTP_XOR_QUAD_CurrentVersionRun_f940 {
  strings:
    $key_f940 = { aa 2f [2] 8e 21 [2] a5 0d [2] 8b 2f [2] 9f 34 [2] 90 2e [2] 8e 33 [2] 8c 32 [2] 97 34 [2] 8b 33 [2] 97 1c }

  condition:
    any of them
}