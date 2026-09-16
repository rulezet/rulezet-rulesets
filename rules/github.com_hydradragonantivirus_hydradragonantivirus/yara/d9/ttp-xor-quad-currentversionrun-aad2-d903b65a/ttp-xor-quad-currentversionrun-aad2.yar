rule TTP_XOR_QUAD_CurrentVersionRun_aad2 {
  strings:
    $key_aad2 = { f9 bd [2] dd b3 [2] f6 9f [2] d8 bd [2] cc a6 [2] c3 bc [2] dd a1 [2] df a0 [2] c4 a6 [2] d8 a1 [2] c4 8e }

  condition:
    any of them
}