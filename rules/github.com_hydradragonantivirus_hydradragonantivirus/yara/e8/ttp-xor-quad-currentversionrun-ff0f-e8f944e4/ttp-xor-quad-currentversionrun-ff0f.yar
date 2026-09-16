rule TTP_XOR_QUAD_CurrentVersionRun_ff0f {
  strings:
    $key_ff0f = { ac 60 [2] 88 6e [2] a3 42 [2] 8d 60 [2] 99 7b [2] 96 61 [2] 88 7c [2] 8a 7d [2] 91 7b [2] 8d 7c [2] 91 53 }

  condition:
    any of them
}