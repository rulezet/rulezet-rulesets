rule TTP_XOR_QUAD_CurrentVersionRun_929f {
  strings:
    $key_929f = { c1 f0 [2] e5 fe [2] ce d2 [2] e0 f0 [2] f4 eb [2] fb f1 [2] e5 ec [2] e7 ed [2] fc eb [2] e0 ec [2] fc c3 }

  condition:
    any of them
}