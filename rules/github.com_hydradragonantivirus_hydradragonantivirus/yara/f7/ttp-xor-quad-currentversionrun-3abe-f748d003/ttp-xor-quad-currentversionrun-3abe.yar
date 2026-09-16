rule TTP_XOR_QUAD_CurrentVersionRun_3abe {
  strings:
    $key_3abe = { 69 d1 [2] 4d df [2] 66 f3 [2] 48 d1 [2] 5c ca [2] 53 d0 [2] 4d cd [2] 4f cc [2] 54 ca [2] 48 cd [2] 54 e2 }

  condition:
    any of them
}