rule TTP_XOR_QUAD_CurrentVersionRun_f835 {
  strings:
    $key_f835 = { ab 5a [2] 8f 54 [2] a4 78 [2] 8a 5a [2] 9e 41 [2] 91 5b [2] 8f 46 [2] 8d 47 [2] 96 41 [2] 8a 46 [2] 96 69 }

  condition:
    any of them
}