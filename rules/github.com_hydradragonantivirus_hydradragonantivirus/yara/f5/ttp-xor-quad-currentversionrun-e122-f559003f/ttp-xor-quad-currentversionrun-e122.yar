rule TTP_XOR_QUAD_CurrentVersionRun_e122 {
  strings:
    $key_e122 = { b2 4d [2] 96 43 [2] bd 6f [2] 93 4d [2] 87 56 [2] 88 4c [2] 96 51 [2] 94 50 [2] 8f 56 [2] 93 51 [2] 8f 7e }

  condition:
    any of them
}