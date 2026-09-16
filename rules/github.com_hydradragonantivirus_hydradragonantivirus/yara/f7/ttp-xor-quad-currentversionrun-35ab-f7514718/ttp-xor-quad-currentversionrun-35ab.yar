rule TTP_XOR_QUAD_CurrentVersionRun_35ab {
  strings:
    $key_35ab = { 66 c4 [2] 42 ca [2] 69 e6 [2] 47 c4 [2] 53 df [2] 5c c5 [2] 42 d8 [2] 40 d9 [2] 5b df [2] 47 d8 [2] 5b f7 }

  condition:
    any of them
}