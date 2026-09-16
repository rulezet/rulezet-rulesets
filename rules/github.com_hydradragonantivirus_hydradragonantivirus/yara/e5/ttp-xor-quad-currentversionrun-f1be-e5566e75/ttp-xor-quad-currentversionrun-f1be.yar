rule TTP_XOR_QUAD_CurrentVersionRun_f1be {
  strings:
    $key_f1be = { a2 d1 [2] 86 df [2] ad f3 [2] 83 d1 [2] 97 ca [2] 98 d0 [2] 86 cd [2] 84 cc [2] 9f ca [2] 83 cd [2] 9f e2 }

  condition:
    any of them
}