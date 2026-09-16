rule TTP_XOR_WriteProcessMemory_06b7 {
  strings:
    $key_06b7 = { 51 c5 [2] 63 e7 [2] 65 d2 [2] 4b d2 [2] 74 ce }

  condition:
    any of them
}