rule TTP_XOR_QUAD_CurrentVersionRun_e1fd {
  strings:
    $key_e1fd = { b2 92 [2] 96 9c [2] bd b0 [2] 93 92 [2] 87 89 [2] 88 93 [2] 96 8e [2] 94 8f [2] 8f 89 [2] 93 8e [2] 8f a1 }

  condition:
    any of them
}