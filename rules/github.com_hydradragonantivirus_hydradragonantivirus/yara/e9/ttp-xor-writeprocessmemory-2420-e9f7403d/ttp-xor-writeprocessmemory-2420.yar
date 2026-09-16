rule TTP_XOR_WriteProcessMemory_2420 {
  strings:
    $key_2420 = { 73 52 [2] 41 70 [2] 47 45 [2] 69 45 [2] 56 59 }

  condition:
    any of them
}