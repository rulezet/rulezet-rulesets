rule TTP_XOR_QUAD_CurrentVersionRun_24b9 {
  strings:
    $key_24b9 = { 77 d6 [2] 53 d8 [2] 78 f4 [2] 56 d6 [2] 42 cd [2] 4d d7 [2] 53 ca [2] 51 cb [2] 4a cd [2] 56 ca [2] 4a e5 }

  condition:
    any of them
}