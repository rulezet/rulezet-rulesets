rule TTP_XOR_WriteProcessMemory_98c8 {
  strings:
    $key_98c8 = { cf ba [2] fd 98 [2] fb ad [2] d5 ad [2] ea b1 }

  condition:
    any of them
}