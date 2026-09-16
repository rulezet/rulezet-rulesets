rule TTP_XOR_QUAD_CurrentVersionRun_cb87 {
  strings:
    $key_cb87 = { 98 e8 [2] bc e6 [2] 97 ca [2] b9 e8 [2] ad f3 [2] a2 e9 [2] bc f4 [2] be f5 [2] a5 f3 [2] b9 f4 [2] a5 db }

  condition:
    any of them
}