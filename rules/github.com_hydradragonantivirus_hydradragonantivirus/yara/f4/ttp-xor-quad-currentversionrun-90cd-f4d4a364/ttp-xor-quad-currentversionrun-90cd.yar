rule TTP_XOR_QUAD_CurrentVersionRun_90cd {
  strings:
    $key_90cd = { c3 a2 [2] e7 ac [2] cc 80 [2] e2 a2 [2] f6 b9 [2] f9 a3 [2] e7 be [2] e5 bf [2] fe b9 [2] e2 be [2] fe 91 }

  condition:
    any of them
}