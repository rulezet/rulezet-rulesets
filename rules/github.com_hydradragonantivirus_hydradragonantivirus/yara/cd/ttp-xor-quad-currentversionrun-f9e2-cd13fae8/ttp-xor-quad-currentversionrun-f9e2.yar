rule TTP_XOR_QUAD_CurrentVersionRun_f9e2 {
  strings:
    $key_f9e2 = { aa 8d [2] 8e 83 [2] a5 af [2] 8b 8d [2] 9f 96 [2] 90 8c [2] 8e 91 [2] 8c 90 [2] 97 96 [2] 8b 91 [2] 97 be }

  condition:
    any of them
}