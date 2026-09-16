rule TTP_XOR_QUAD_CurrentVersionRun_dee2 {
  strings:
    $key_dee2 = { 8d 8d [2] a9 83 [2] 82 af [2] ac 8d [2] b8 96 [2] b7 8c [2] a9 91 [2] ab 90 [2] b0 96 [2] ac 91 [2] b0 be }

  condition:
    any of them
}