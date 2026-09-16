rule TTP_XOR_WriteProcessMemory_9fa0 {
  strings:
    $key_9fa0 = { c8 d2 [2] fa f0 [2] fc c5 [2] d2 c5 [2] ed d9 }

  condition:
    any of them
}