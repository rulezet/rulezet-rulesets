rule TTP_XOR_QUAD_CurrentVersionRun_eabe {
  strings:
    $key_eabe = { b9 d1 [2] 9d df [2] b6 f3 [2] 98 d1 [2] 8c ca [2] 83 d0 [2] 9d cd [2] 9f cc [2] 84 ca [2] 98 cd [2] 84 e2 }

  condition:
    any of them
}