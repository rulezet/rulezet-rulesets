rule TTP_XOR_QUAD_CurrentVersionRun_cb85 {
  strings:
    $key_cb85 = { 98 ea [2] bc e4 [2] 97 c8 [2] b9 ea [2] ad f1 [2] a2 eb [2] bc f6 [2] be f7 [2] a5 f1 [2] b9 f6 [2] a5 d9 }

  condition:
    any of them
}