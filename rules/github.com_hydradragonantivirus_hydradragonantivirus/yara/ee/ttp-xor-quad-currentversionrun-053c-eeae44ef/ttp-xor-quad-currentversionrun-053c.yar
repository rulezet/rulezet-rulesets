rule TTP_XOR_QUAD_CurrentVersionRun_053c {
  strings:
    $key_053c = { 56 53 [2] 72 5d [2] 59 71 [2] 77 53 [2] 63 48 [2] 6c 52 [2] 72 4f [2] 70 4e [2] 6b 48 [2] 77 4f [2] 6b 60 }

  condition:
    any of them
}