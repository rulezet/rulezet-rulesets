rule TTP_XOR_QUAD_CurrentVersionRun_cbd7 {
  strings:
    $key_cbd7 = { 98 b8 [2] bc b6 [2] 97 9a [2] b9 b8 [2] ad a3 [2] a2 b9 [2] bc a4 [2] be a5 [2] a5 a3 [2] b9 a4 [2] a5 8b }

  condition:
    any of them
}