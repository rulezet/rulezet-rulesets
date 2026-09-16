rule TTP_XOR_QUAD_CurrentVersionRun_cb98 {
  strings:
    $key_cb98 = { 98 f7 [2] bc f9 [2] 97 d5 [2] b9 f7 [2] ad ec [2] a2 f6 [2] bc eb [2] be ea [2] a5 ec [2] b9 eb [2] a5 c4 }

  condition:
    any of them
}