rule TTP_XOR_QUAD_CurrentVersionRun_f814 {
  strings:
    $key_f814 = { ab 7b [2] 8f 75 [2] a4 59 [2] 8a 7b [2] 9e 60 [2] 91 7a [2] 8f 67 [2] 8d 66 [2] 96 60 [2] 8a 67 [2] 96 48 }

  condition:
    any of them
}