rule TTP_XOR_QUAD_CurrentVersionRun_feb9 {
  strings:
    $key_feb9 = { ad d6 [2] 89 d8 [2] a2 f4 [2] 8c d6 [2] 98 cd [2] 97 d7 [2] 89 ca [2] 8b cb [2] 90 cd [2] 8c ca [2] 90 e5 }

  condition:
    any of them
}