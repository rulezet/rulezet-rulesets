rule TTP_XOR_QUAD_CurrentVersionRun_f838 {
  strings:
    $key_f838 = { ab 57 [2] 8f 59 [2] a4 75 [2] 8a 57 [2] 9e 4c [2] 91 56 [2] 8f 4b [2] 8d 4a [2] 96 4c [2] 8a 4b [2] 96 64 }

  condition:
    any of them
}