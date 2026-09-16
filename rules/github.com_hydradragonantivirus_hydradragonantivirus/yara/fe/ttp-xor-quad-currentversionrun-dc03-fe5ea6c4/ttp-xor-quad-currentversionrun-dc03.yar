rule TTP_XOR_QUAD_CurrentVersionRun_dc03 {
  strings:
    $key_dc03 = { 8f 6c [2] ab 62 [2] 80 4e [2] ae 6c [2] ba 77 [2] b5 6d [2] ab 70 [2] a9 71 [2] b2 77 [2] ae 70 [2] b2 5f }

  condition:
    any of them
}