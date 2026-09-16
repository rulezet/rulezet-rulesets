rule TTP_XOR_QUAD_CurrentVersionRun_cbd6 {
  strings:
    $key_cbd6 = { 98 b9 [2] bc b7 [2] 97 9b [2] b9 b9 [2] ad a2 [2] a2 b8 [2] bc a5 [2] be a4 [2] a5 a2 [2] b9 a5 [2] a5 8a }

  condition:
    any of them
}