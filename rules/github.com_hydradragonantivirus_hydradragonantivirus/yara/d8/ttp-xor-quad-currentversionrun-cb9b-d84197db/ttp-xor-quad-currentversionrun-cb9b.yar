rule TTP_XOR_QUAD_CurrentVersionRun_cb9b {
  strings:
    $key_cb9b = { 98 f4 [2] bc fa [2] 97 d6 [2] b9 f4 [2] ad ef [2] a2 f5 [2] bc e8 [2] be e9 [2] a5 ef [2] b9 e8 [2] a5 c7 }

  condition:
    any of them
}