rule TTP_XOR_QUAD_CurrentVersionRun_cbb1 {
  strings:
    $key_cbb1 = { 98 de [2] bc d0 [2] 97 fc [2] b9 de [2] ad c5 [2] a2 df [2] bc c2 [2] be c3 [2] a5 c5 [2] b9 c2 [2] a5 ed }

  condition:
    any of them
}