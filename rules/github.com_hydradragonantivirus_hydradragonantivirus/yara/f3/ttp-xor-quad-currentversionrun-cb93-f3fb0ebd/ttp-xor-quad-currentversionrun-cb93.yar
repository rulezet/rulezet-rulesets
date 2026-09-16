rule TTP_XOR_QUAD_CurrentVersionRun_cb93 {
  strings:
    $key_cb93 = { 98 fc [2] bc f2 [2] 97 de [2] b9 fc [2] ad e7 [2] a2 fd [2] bc e0 [2] be e1 [2] a5 e7 [2] b9 e0 [2] a5 cf }

  condition:
    any of them
}