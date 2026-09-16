rule TTP_XOR_WriteProcessMemory_87ba {
  strings:
    $key_87ba = { d0 c8 [2] e2 ea [2] e4 df [2] ca df [2] f5 c3 }

  condition:
    any of them
}