rule TTP_XOR_WriteProcessMemory_a0fd {
  strings:
    $key_a0fd = { f7 8f [2] c5 ad [2] c3 98 [2] ed 98 [2] d2 84 }

  condition:
    any of them
}