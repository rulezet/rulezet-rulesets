rule TTP_XOR_QUAD_CurrentVersionRun_ff20 {
  strings:
    $key_ff20 = { ac 4f [2] 88 41 [2] a3 6d [2] 8d 4f [2] 99 54 [2] 96 4e [2] 88 53 [2] 8a 52 [2] 91 54 [2] 8d 53 [2] 91 7c }

  condition:
    any of them
}