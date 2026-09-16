rule TTP_XOR_QUAD_CurrentVersionRun_979f {
  strings:
    $key_979f = { c4 f0 [2] e0 fe [2] cb d2 [2] e5 f0 [2] f1 eb [2] fe f1 [2] e0 ec [2] e2 ed [2] f9 eb [2] e5 ec [2] f9 c3 }

  condition:
    any of them
}