rule TTP_XOR_QUAD_CurrentVersionRun_dc11 {
  strings:
    $key_dc11 = { 8f 7e [2] ab 70 [2] 80 5c [2] ae 7e [2] ba 65 [2] b5 7f [2] ab 62 [2] a9 63 [2] b2 65 [2] ae 62 [2] b2 4d }

  condition:
    any of them
}