rule TTP_XOR_QUAD_CurrentVersionRun_dc3e {
  strings:
    $key_dc3e = { 8f 51 [2] ab 5f [2] 80 73 [2] ae 51 [2] ba 4a [2] b5 50 [2] ab 4d [2] a9 4c [2] b2 4a [2] ae 4d [2] b2 62 }

  condition:
    any of them
}