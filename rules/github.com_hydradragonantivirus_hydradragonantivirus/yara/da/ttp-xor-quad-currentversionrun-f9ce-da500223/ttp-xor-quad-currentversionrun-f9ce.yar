rule TTP_XOR_QUAD_CurrentVersionRun_f9ce {
  strings:
    $key_f9ce = { aa a1 [2] 8e af [2] a5 83 [2] 8b a1 [2] 9f ba [2] 90 a0 [2] 8e bd [2] 8c bc [2] 97 ba [2] 8b bd [2] 97 92 }

  condition:
    any of them
}