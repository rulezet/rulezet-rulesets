rule TTP_XOR_QUAD_CurrentVersionRun_a2ab {
  strings:
    $key_a2ab = { f1 c4 [2] d5 ca [2] fe e6 [2] d0 c4 [2] c4 df [2] cb c5 [2] d5 d8 [2] d7 d9 [2] cc df [2] d0 d8 [2] cc f7 }

  condition:
    any of them
}