rule TTP_XOR_QUAD_CurrentVersionRun_f912 {
  strings:
    $key_f912 = { aa 7d [2] 8e 73 [2] a5 5f [2] 8b 7d [2] 9f 66 [2] 90 7c [2] 8e 61 [2] 8c 60 [2] 97 66 [2] 8b 61 [2] 97 4e }

  condition:
    any of them
}