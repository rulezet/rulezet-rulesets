rule TTP_XOR_QUAD_CurrentVersionRun_0bbe {
  strings:
    $key_0bbe = { 58 d1 [2] 7c df [2] 57 f3 [2] 79 d1 [2] 6d ca [2] 62 d0 [2] 7c cd [2] 7e cc [2] 65 ca [2] 79 cd [2] 65 e2 }

  condition:
    any of them
}