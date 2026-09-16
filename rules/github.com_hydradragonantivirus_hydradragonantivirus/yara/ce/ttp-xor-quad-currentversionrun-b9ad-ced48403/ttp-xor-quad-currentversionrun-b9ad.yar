rule TTP_XOR_QUAD_CurrentVersionRun_b9ad {
  strings:
    $key_b9ad = { ea c2 [2] ce cc [2] e5 e0 [2] cb c2 [2] df d9 [2] d0 c3 [2] ce de [2] cc df [2] d7 d9 [2] cb de [2] d7 f1 }

  condition:
    any of them
}