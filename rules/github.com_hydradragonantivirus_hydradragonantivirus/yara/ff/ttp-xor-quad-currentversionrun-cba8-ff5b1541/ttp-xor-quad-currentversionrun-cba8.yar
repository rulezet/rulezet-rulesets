rule TTP_XOR_QUAD_CurrentVersionRun_cba8 {
  strings:
    $key_cba8 = { 98 c7 [2] bc c9 [2] 97 e5 [2] b9 c7 [2] ad dc [2] a2 c6 [2] bc db [2] be da [2] a5 dc [2] b9 db [2] a5 f4 }

  condition:
    any of them
}