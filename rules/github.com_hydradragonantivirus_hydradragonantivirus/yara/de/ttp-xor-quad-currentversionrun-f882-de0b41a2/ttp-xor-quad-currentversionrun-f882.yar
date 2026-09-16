rule TTP_XOR_QUAD_CurrentVersionRun_f882 {
  strings:
    $key_f882 = { ab ed [2] 8f e3 [2] a4 cf [2] 8a ed [2] 9e f6 [2] 91 ec [2] 8f f1 [2] 8d f0 [2] 96 f6 [2] 8a f1 [2] 96 de }

  condition:
    any of them
}