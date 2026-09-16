rule TTP_XOR_QUAD_CurrentVersionRun_e418 {
  strings:
    $key_e418 = { b7 77 [2] 93 79 [2] b8 55 [2] 96 77 [2] 82 6c [2] 8d 76 [2] 93 6b [2] 91 6a [2] 8a 6c [2] 96 6b [2] 8a 44 }

  condition:
    any of them
}