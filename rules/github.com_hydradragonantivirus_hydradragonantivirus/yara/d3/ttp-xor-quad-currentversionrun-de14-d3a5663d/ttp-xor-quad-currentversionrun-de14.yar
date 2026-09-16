rule TTP_XOR_QUAD_CurrentVersionRun_de14 {
  strings:
    $key_de14 = { 8d 7b [2] a9 75 [2] 82 59 [2] ac 7b [2] b8 60 [2] b7 7a [2] a9 67 [2] ab 66 [2] b0 60 [2] ac 67 [2] b0 48 }

  condition:
    any of them
}