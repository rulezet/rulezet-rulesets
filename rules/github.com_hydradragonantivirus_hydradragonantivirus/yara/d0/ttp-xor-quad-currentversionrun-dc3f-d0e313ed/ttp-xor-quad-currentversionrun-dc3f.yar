rule TTP_XOR_QUAD_CurrentVersionRun_dc3f {
  strings:
    $key_dc3f = { 8f 50 [2] ab 5e [2] 80 72 [2] ae 50 [2] ba 4b [2] b5 51 [2] ab 4c [2] a9 4d [2] b2 4b [2] ae 4c [2] b2 63 }

  condition:
    any of them
}