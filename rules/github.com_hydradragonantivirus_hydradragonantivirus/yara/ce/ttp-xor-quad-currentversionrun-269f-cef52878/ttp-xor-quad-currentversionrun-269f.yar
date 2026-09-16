rule TTP_XOR_QUAD_CurrentVersionRun_269f {
  strings:
    $key_269f = { 75 f0 [2] 51 fe [2] 7a d2 [2] 54 f0 [2] 40 eb [2] 4f f1 [2] 51 ec [2] 53 ed [2] 48 eb [2] 54 ec [2] 48 c3 }

  condition:
    any of them
}