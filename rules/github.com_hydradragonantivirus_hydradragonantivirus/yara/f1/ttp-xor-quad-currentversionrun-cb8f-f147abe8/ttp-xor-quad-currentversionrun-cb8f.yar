rule TTP_XOR_QUAD_CurrentVersionRun_cb8f {
  strings:
    $key_cb8f = { 98 e0 [2] bc ee [2] 97 c2 [2] b9 e0 [2] ad fb [2] a2 e1 [2] bc fc [2] be fd [2] a5 fb [2] b9 fc [2] a5 d3 }

  condition:
    any of them
}