rule TTP_XOR_QUAD_CurrentVersionRun_f896 {
  strings:
    $key_f896 = { ab f9 [2] 8f f7 [2] a4 db [2] 8a f9 [2] 9e e2 [2] 91 f8 [2] 8f e5 [2] 8d e4 [2] 96 e2 [2] 8a e5 [2] 96 ca }

  condition:
    any of them
}