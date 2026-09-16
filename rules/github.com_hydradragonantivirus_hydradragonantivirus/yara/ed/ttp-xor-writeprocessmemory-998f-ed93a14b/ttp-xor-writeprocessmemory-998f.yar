rule TTP_XOR_WriteProcessMemory_998f {
  strings:
    $key_998f = { ce fd [2] fc df [2] fa ea [2] d4 ea [2] eb f6 }

  condition:
    any of them
}