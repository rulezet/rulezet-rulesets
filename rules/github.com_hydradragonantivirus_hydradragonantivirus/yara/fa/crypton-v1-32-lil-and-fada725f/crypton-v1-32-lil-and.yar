rule Crypton_v1__32_lil_AND_ {
  strings:
    $a0 = { ac ac ac ac [0-20] 59 59 59 59 [0-20] b2 b2 b2 b2 [0-20] 65 65 65 65 [0-20] 01 01 01 01 [0-20] fc f3 cf 3f [0-20] f3 cf 3f fc [0-20] cf 3f fc f3 [0-20] 3f fc f3 cf }

  condition:
    $a0
}