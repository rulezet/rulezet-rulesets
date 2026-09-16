rule TTP_XOR_QUAD_CurrentVersionRun_cbd9 {
  strings:
    $key_cbd9 = { 98 b6 [2] bc b8 [2] 97 94 [2] b9 b6 [2] ad ad [2] a2 b7 [2] bc aa [2] be ab [2] a5 ad [2] b9 aa [2] a5 85 }

  condition:
    any of them
}