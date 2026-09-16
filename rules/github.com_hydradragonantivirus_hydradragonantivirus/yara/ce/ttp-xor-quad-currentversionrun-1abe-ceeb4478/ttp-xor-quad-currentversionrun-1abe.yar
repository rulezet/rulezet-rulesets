rule TTP_XOR_QUAD_CurrentVersionRun_1abe {
  strings:
    $key_1abe = { 49 d1 [2] 6d df [2] 46 f3 [2] 68 d1 [2] 7c ca [2] 73 d0 [2] 6d cd [2] 6f cc [2] 74 ca [2] 68 cd [2] 74 e2 }

  condition:
    any of them
}