rule TTP_XOR_QUAD_CurrentVersionRun_f926 {
  strings:
    $key_f926 = { aa 49 [2] 8e 47 [2] a5 6b [2] 8b 49 [2] 9f 52 [2] 90 48 [2] 8e 55 [2] 8c 54 [2] 97 52 [2] 8b 55 [2] 97 7a }

  condition:
    any of them
}