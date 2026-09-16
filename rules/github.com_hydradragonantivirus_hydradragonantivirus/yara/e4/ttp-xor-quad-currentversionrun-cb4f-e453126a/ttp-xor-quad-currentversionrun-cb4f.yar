rule TTP_XOR_QUAD_CurrentVersionRun_cb4f {
  strings:
    $key_cb4f = { 98 20 [2] bc 2e [2] 97 02 [2] b9 20 [2] ad 3b [2] a2 21 [2] bc 3c [2] be 3d [2] a5 3b [2] b9 3c [2] a5 13 }

  condition:
    any of them
}