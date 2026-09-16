rule TTP_XOR_QUAD_CurrentVersionRun_cb84 {
  strings:
    $key_cb84 = { 98 eb [2] bc e5 [2] 97 c9 [2] b9 eb [2] ad f0 [2] a2 ea [2] bc f7 [2] be f6 [2] a5 f0 [2] b9 f7 [2] a5 d8 }

  condition:
    any of them
}