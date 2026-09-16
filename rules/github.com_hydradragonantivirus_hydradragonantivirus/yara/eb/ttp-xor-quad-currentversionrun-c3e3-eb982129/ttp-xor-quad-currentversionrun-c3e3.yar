rule TTP_XOR_QUAD_CurrentVersionRun_c3e3 {
  strings:
    $key_c3e3 = { 90 8c [2] b4 82 [2] 9f ae [2] b1 8c [2] a5 97 [2] aa 8d [2] b4 90 [2] b6 91 [2] ad 97 [2] b1 90 [2] ad bf }

  condition:
    any of them
}