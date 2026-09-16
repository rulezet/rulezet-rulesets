rule TTP_XOR_QUAD_CurrentVersionRun_caf0 {
  strings:
    $key_caf0 = { 99 9f [2] bd 91 [2] 96 bd [2] b8 9f [2] ac 84 [2] a3 9e [2] bd 83 [2] bf 82 [2] a4 84 [2] b8 83 [2] a4 ac }

  condition:
    any of them
}