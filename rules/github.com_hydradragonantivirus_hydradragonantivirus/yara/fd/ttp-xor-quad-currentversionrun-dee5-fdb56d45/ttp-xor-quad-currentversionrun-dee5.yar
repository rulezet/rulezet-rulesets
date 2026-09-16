rule TTP_XOR_QUAD_CurrentVersionRun_dee5 {
  strings:
    $key_dee5 = { 8d 8a [2] a9 84 [2] 82 a8 [2] ac 8a [2] b8 91 [2] b7 8b [2] a9 96 [2] ab 97 [2] b0 91 [2] ac 96 [2] b0 b9 }

  condition:
    any of them
}