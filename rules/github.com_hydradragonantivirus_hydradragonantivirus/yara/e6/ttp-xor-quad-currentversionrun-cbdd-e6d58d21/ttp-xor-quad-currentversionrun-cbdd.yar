rule TTP_XOR_QUAD_CurrentVersionRun_cbdd {
  strings:
    $key_cbdd = { 98 b2 [2] bc bc [2] 97 90 [2] b9 b2 [2] ad a9 [2] a2 b3 [2] bc ae [2] be af [2] a5 a9 [2] b9 ae [2] a5 81 }

  condition:
    any of them
}