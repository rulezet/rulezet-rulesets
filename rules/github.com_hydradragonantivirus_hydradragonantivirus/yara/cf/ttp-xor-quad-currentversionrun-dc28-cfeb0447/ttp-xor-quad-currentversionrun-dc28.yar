rule TTP_XOR_QUAD_CurrentVersionRun_dc28 {
  strings:
    $key_dc28 = { 8f 47 [2] ab 49 [2] 80 65 [2] ae 47 [2] ba 5c [2] b5 46 [2] ab 5b [2] a9 5a [2] b2 5c [2] ae 5b [2] b2 74 }

  condition:
    any of them
}