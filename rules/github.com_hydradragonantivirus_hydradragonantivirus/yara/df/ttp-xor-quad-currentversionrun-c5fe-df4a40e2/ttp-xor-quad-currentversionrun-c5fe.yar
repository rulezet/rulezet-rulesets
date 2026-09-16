rule TTP_XOR_QUAD_CurrentVersionRun_c5fe {
  strings:
    $key_c5fe = { 96 91 [2] b2 9f [2] 99 b3 [2] b7 91 [2] a3 8a [2] ac 90 [2] b2 8d [2] b0 8c [2] ab 8a [2] b7 8d [2] ab a2 }

  condition:
    any of them
}