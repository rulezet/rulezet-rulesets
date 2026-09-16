rule TTP_XOR_QUAD_CurrentVersionRun_6589 {
  strings:
    $key_6589 = { 36 e6 [2] 12 e8 [2] 39 c4 [2] 17 e6 [2] 03 fd [2] 0c e7 [2] 12 fa [2] 10 fb [2] 0b fd [2] 17 fa [2] 0b d5 }

  condition:
    any of them
}