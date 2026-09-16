rule TTP_XOR_QUAD_CurrentVersionRun_e63c {
  strings:
    $key_e63c = { b5 53 [2] 91 5d [2] ba 71 [2] 94 53 [2] 80 48 [2] 8f 52 [2] 91 4f [2] 93 4e [2] 88 48 [2] 94 4f [2] 88 60 }

  condition:
    any of them
}