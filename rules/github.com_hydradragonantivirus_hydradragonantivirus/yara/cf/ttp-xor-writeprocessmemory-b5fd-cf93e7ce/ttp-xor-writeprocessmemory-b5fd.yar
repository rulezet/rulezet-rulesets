rule TTP_XOR_WriteProcessMemory_b5fd {
  strings:
    $key_b5fd = { e2 8f [2] d0 ad [2] d6 98 [2] f8 98 [2] c7 84 }

  condition:
    any of them
}