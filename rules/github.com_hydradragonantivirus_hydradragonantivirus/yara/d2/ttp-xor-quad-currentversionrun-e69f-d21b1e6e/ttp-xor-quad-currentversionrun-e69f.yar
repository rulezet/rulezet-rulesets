rule TTP_XOR_QUAD_CurrentVersionRun_e69f {
  strings:
    $key_e69f = { b5 f0 [2] 91 fe [2] ba d2 [2] 94 f0 [2] 80 eb [2] 8f f1 [2] 91 ec [2] 93 ed [2] 88 eb [2] 94 ec [2] 88 c3 }

  condition:
    any of them
}