rule TTP_XOR_QUAD_CurrentVersionRun_1bbe {
  strings:
    $key_1bbe = { 48 d1 [2] 6c df [2] 47 f3 [2] 69 d1 [2] 7d ca [2] 72 d0 [2] 6c cd [2] 6e cc [2] 75 ca [2] 69 cd [2] 75 e2 }

  condition:
    any of them
}