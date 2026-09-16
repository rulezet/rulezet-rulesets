rule TTP_XOR_QUAD_CurrentVersionRun_dc3b {
  strings:
    $key_dc3b = { 8f 54 [2] ab 5a [2] 80 76 [2] ae 54 [2] ba 4f [2] b5 55 [2] ab 48 [2] a9 49 [2] b2 4f [2] ae 48 [2] b2 67 }

  condition:
    any of them
}