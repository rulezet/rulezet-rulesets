rule TTP_XOR_QUAD_CurrentVersionRun_c214 {
  strings:
    $key_c214 = { 91 7b [2] b5 75 [2] 9e 59 [2] b0 7b [2] a4 60 [2] ab 7a [2] b5 67 [2] b7 66 [2] ac 60 [2] b0 67 [2] ac 48 }

  condition:
    any of them
}