rule TTP_XOR_QUAD_CurrentVersionRun_928c {
  strings:
    $key_928c = { c1 e3 [2] e5 ed [2] ce c1 [2] e0 e3 [2] f4 f8 [2] fb e2 [2] e5 ff [2] e7 fe [2] fc f8 [2] e0 ff [2] fc d0 }

  condition:
    any of them
}