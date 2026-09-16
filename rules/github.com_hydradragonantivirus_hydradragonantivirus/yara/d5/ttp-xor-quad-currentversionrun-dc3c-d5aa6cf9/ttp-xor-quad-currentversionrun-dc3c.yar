rule TTP_XOR_QUAD_CurrentVersionRun_dc3c {
  strings:
    $key_dc3c = { 8f 53 [2] ab 5d [2] 80 71 [2] ae 53 [2] ba 48 [2] b5 52 [2] ab 4f [2] a9 4e [2] b2 48 [2] ae 4f [2] b2 60 }

  condition:
    any of them
}