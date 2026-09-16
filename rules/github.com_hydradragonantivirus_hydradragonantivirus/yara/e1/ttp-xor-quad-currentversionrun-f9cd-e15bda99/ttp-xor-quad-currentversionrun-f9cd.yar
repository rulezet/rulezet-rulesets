rule TTP_XOR_QUAD_CurrentVersionRun_f9cd {
  strings:
    $key_f9cd = { aa a2 [2] 8e ac [2] a5 80 [2] 8b a2 [2] 9f b9 [2] 90 a3 [2] 8e be [2] 8c bf [2] 97 b9 [2] 8b be [2] 97 91 }

  condition:
    any of them
}