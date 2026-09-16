rule TTP_XOR_QUAD_CurrentVersionRun_dc7b {
  strings:
    $key_dc7b = { 8f 14 [2] ab 1a [2] 80 36 [2] ae 14 [2] ba 0f [2] b5 15 [2] ab 08 [2] a9 09 [2] b2 0f [2] ae 08 [2] b2 27 }

  condition:
    any of them
}