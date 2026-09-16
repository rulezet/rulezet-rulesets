rule TTP_XOR_QUAD_CurrentVersionRun_cf3b {
  strings:
    $key_cf3b = { 9c 54 [2] b8 5a [2] 93 76 [2] bd 54 [2] a9 4f [2] a6 55 [2] b8 48 [2] ba 49 [2] a1 4f [2] bd 48 [2] a1 67 }

  condition:
    any of them
}