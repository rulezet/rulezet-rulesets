rule TTP_XOR_WriteProcessMemory_d9b7 {
  strings:
    $key_d9b7 = { 8e c5 [2] bc e7 [2] ba d2 [2] 94 d2 [2] ab ce }

  condition:
    any of them
}