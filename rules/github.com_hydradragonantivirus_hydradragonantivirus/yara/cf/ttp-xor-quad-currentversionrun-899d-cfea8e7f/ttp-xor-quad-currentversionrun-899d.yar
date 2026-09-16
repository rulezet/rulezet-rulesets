rule TTP_XOR_QUAD_CurrentVersionRun_899d {
  strings:
    $key_899d = { da f2 [2] fe fc [2] d5 d0 [2] fb f2 [2] ef e9 [2] e0 f3 [2] fe ee [2] fc ef [2] e7 e9 [2] fb ee [2] e7 c1 }

  condition:
    any of them
}