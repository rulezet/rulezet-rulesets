rule TTP_XOR_WriteProcessMemory_b1ad {
  strings:
    $key_b1ad = { e6 df [2] d4 fd [2] d2 c8 [2] fc c8 [2] c3 d4 }

  condition:
    any of them
}