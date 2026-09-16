rule TTP_XOR_QUAD_CurrentVersionRun_233f {
  strings:
    $key_233f = { 70 50 [2] 54 5e [2] 7f 72 [2] 51 50 [2] 45 4b [2] 4a 51 [2] 54 4c [2] 56 4d [2] 4d 4b [2] 51 4c [2] 4d 63 }

  condition:
    any of them
}