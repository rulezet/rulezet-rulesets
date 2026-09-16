rule TTP_XOR_QUAD_CurrentVersionRun_cb89 {
  strings:
    $key_cb89 = { 98 e6 [2] bc e8 [2] 97 c4 [2] b9 e6 [2] ad fd [2] a2 e7 [2] bc fa [2] be fb [2] a5 fd [2] b9 fa [2] a5 d5 }

  condition:
    any of them
}