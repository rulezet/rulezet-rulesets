rule TTP_XOR_QUAD_CurrentVersionRun_d326 {
  strings:
    $key_d326 = { 80 49 [2] a4 47 [2] 8f 6b [2] a1 49 [2] b5 52 [2] ba 48 [2] a4 55 [2] a6 54 [2] bd 52 [2] a1 55 [2] bd 7a }

  condition:
    any of them
}