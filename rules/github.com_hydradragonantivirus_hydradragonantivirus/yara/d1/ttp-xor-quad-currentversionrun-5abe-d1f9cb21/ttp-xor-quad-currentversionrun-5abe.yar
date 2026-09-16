rule TTP_XOR_QUAD_CurrentVersionRun_5abe {
  strings:
    $key_5abe = { 09 d1 [2] 2d df [2] 06 f3 [2] 28 d1 [2] 3c ca [2] 33 d0 [2] 2d cd [2] 2f cc [2] 34 ca [2] 28 cd [2] 34 e2 }

  condition:
    any of them
}