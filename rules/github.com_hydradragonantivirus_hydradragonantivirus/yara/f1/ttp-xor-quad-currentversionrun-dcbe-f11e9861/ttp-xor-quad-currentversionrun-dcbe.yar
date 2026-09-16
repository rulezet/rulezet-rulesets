rule TTP_XOR_QUAD_CurrentVersionRun_dcbe {
  strings:
    $key_dcbe = { 8f d1 [2] ab df [2] 80 f3 [2] ae d1 [2] ba ca [2] b5 d0 [2] ab cd [2] a9 cc [2] b2 ca [2] ae cd [2] b2 e2 }

  condition:
    any of them
}