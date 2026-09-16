rule TTP_XOR_QUAD_CurrentVersionRun_cb0a {
  strings:
    $key_cb0a = { 98 65 [2] bc 6b [2] 97 47 [2] b9 65 [2] ad 7e [2] a2 64 [2] bc 79 [2] be 78 [2] a5 7e [2] b9 79 [2] a5 56 }

  condition:
    any of them
}