rule TTP_XOR_QUAD_CurrentVersionRun_cb90 {
  strings:
    $key_cb90 = { 98 ff [2] bc f1 [2] 97 dd [2] b9 ff [2] ad e4 [2] a2 fe [2] bc e3 [2] be e2 [2] a5 e4 [2] b9 e3 [2] a5 cc }

  condition:
    any of them
}