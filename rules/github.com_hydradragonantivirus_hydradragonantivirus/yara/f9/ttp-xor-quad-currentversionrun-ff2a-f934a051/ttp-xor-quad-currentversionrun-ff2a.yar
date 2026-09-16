rule TTP_XOR_QUAD_CurrentVersionRun_ff2a {
  strings:
    $key_ff2a = { ac 45 [2] 88 4b [2] a3 67 [2] 8d 45 [2] 99 5e [2] 96 44 [2] 88 59 [2] 8a 58 [2] 91 5e [2] 8d 59 [2] 91 76 }

  condition:
    any of them
}