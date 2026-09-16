rule TTP_XOR_QUAD_CurrentVersionRun_a214 {
  strings:
    $key_a214 = { f1 7b [2] d5 75 [2] fe 59 [2] d0 7b [2] c4 60 [2] cb 7a [2] d5 67 [2] d7 66 [2] cc 60 [2] d0 67 [2] cc 48 }

  condition:
    any of them
}