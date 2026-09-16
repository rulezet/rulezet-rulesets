rule TTP_XOR_QUAD_CurrentVersionRun_dc29 {
  strings:
    $key_dc29 = { 8f 46 [2] ab 48 [2] 80 64 [2] ae 46 [2] ba 5d [2] b5 47 [2] ab 5a [2] a9 5b [2] b2 5d [2] ae 5a [2] b2 75 }

  condition:
    any of them
}