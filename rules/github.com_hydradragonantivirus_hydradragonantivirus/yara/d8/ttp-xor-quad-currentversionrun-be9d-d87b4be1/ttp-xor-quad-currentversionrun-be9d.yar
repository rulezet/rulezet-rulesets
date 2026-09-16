rule TTP_XOR_QUAD_CurrentVersionRun_be9d {
  strings:
    $key_be9d = { ed f2 [2] c9 fc [2] e2 d0 [2] cc f2 [2] d8 e9 [2] d7 f3 [2] c9 ee [2] cb ef [2] d0 e9 [2] cc ee [2] d0 c1 }

  condition:
    any of them
}